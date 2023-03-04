import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Generate access token
const generateAccessToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.ACCESS_SECRET, {
        expiresIn: '300s',
    });
};

// Generate refresh token
const generateRefreshToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.REFRESH_SECRET, {
        expiresIn: '1d',
    });
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

        await User.findByIdAndUpdate(user._id, { $push: { refreshTokens: refreshToken } });

        res.status(200).json({ accessToken: accessToken, refreshToken: refreshToken });
    } catch (err) {
        next(err);
    }
};

// Get current user controller
export const getCurrentUserHandler = async (req, res, next) => {
    try {
        const currentUser = await User.findById(req.user._id);
        res.status(200).json(currentUser);
    } catch (error) {
        next(error);
    }
};

// Refresh token controller
export const refreshHandler = async (req, res) => {
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

        await User.findByIdAndUpdate(currUser._id, { $push: { refreshTokens: newRefreshToken } });

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    });
};

// Sign out controller
export const signOutHandler = async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, { $set: { refreshTokens: [] } });
    res.status(200).json('You logged out successfully.');
};
