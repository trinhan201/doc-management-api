import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

let refreshTokens = [];

// Generate access token
const generateAccessToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.ACCESS_SECRET, {
        expiresIn: '30s',
    });
};

// Generate refresh token
const generateRefreshToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.REFRESH_SECRET, {
        expiresIn: '1d',
    });
};

// Sign up controller
export const signUpHandler = async (req, res, next) => {
    try {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        const newUser = new User({ ...req.body, password: hash });

        await newUser.save();
        res.status(200).send('User has been created!');
    } catch (err) {
        next(err);
    }
};

// Sign in controller
export const signInHandler = async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) return res.status(404).json({ code: 404, message: 'User not found!' });

        const isCorrect = await bcrypt.compare(req.body.password, user.password);

        if (!isCorrect) return res.status(400).json({ code: 400, message: 'Wrong Credentials!' });

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        // refreshTokens.push(refreshToken);

        await User.findByIdAndUpdate(user._id, { $push: { refreshTokens: refreshToken } });

        res.status(200).json({ accessToken: accessToken, refreshToken: refreshToken });
    } catch (err) {
        next(err);
    }
};

// Get current user controller
export const getCurrentUserController = async (req, res, next) => {
    try {
        const currentUser = await User.findById(req.user._id);
        res.status(200).json(currentUser);
    } catch (error) {
        next(error);
    }
};

// Refresh token controller
export const refreshController = async (req, res) => {
    const currUser = await User.findById(req.params.id);

    const refreshToken = req.body.token;
    if (!refreshToken) return res.status(401).json('You are not authenticated!');
    if (!currUser.refreshTokens.includes(refreshToken)) {
        return res.status(403).json('Refresh token is not valid!');
    }
    jwt.verify(refreshToken, process.env.REFRESH_SECRET, async (err, user) => {
        err && console.log(err);
        currUser.refreshTokens = currUser.refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        // refreshTokens.push(newRefreshToken);
        await User.findByIdAndUpdate(currUser._id, { $push: { refreshTokens: newRefreshToken } });

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    });
};
