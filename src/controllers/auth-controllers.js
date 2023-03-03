import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

let refreshTokens = [];

const generateAccessToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.ACCESS_SECRET, {
        expiresIn: '300s',
    });
};

const generateRefreshToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.REFRESH_SECRET, {
        expiresIn: '1d',
    });
};

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

export const signInHandler = async (req, res, next) => {
    try {
        const user = await User.findOne({ userName: req.body.userName });
        if (!user) return res.status(404).json({ code: 404, message: 'User not found!' });

        const isCorrect = await bcrypt.compare(req.body.password, user.password);

        if (!isCorrect) return res.status(400).json({ code: 400, message: 'Wrong Credentials!' });

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);

        res.status(200).json({ accessToken: accessToken, refreshToken: refreshToken });
    } catch (err) {
        next(err);
    }
};
