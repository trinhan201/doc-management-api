import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodeMailer from 'nodemailer';

// Generate access token
const generateAccessToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.ACCESS_SECRET, {
        expiresIn: '500s',
    });
};

// Generate refresh token
const generateRefreshToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.REFRESH_SECRET, {
        expiresIn: '1d',
    });
};

// Generate reset password token
const generateResetPasswordToken = (user) => {
    return jwt.sign({ _id: user._id, email: user.email }, process.env.RESET_PASS_SECRET, {
        expiresIn: '30s',
    });
};

// Send mail
const sendResetPasswordMail = async (name, email, token) => {
    try {
        const transporter = nodeMailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            requireTLS: true,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'For Reset Password',
            html: `<p> Hello ${name}, Please copy the link and <a href="${process.env.CLIENT_URL}/api/v1/auth/reset-password?token=${token}"> reset your password</a>`,
        };
        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Mail has been sent', info.response);
            }
        });
    } catch (error) {
        res.status(400).send(error);
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
    const currUser = await User.findById(req.params.userId);

    const refreshToken = req.body.token;
    if (!refreshToken) return res.status(401).json({ code: 401, message: 'You are not authenticated!' });
    if (!currUser.refreshTokens.includes(refreshToken)) {
        return res.status(403).json({ code: 403, message: 'Refresh token is not valid!' });
    }
    jwt.verify(refreshToken, process.env.REFRESH_SECRET, async (err, user) => {
        err && console.log(err);
        // currUser.refreshTokens = currUser.refreshTokens.filter((token) => token !== refreshToken);

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

// Forgot password controller
export const forgotPasswordHandler = async (req, res, next) => {
    try {
        const email = req.body.email;
        const userData = await User.findOne({ email: email });
        if (userData) {
            const token = generateResetPasswordToken(userData);
            await User.updateOne({ email: email }, { $set: { resetPasswordToken: token } });
            sendResetPasswordMail(userData.userName, userData.email, token);
            res.status(200).json({ code: 200, message: 'PLease check your inbox of mail and reset your password' });
        } else {
            res.status(200).json({ code: 200, message: 'This email does not exist' });
        }
    } catch (error) {
        next(error);
    }
};

// Reset password controller
export const resetPasswordHandler = async (req, res, next) => {
    try {
        const token = req.query.token;
        jwt.verify(token, process.env.RESET_PASS_SECRET, async (err, user) => {
            if (err) {
                return res.status(403).json({ code: 403, message: 'Token is not valid or it is expired' });
            }

            const salt = bcrypt.genSaltSync(10);
            const newPassword = bcrypt.hashSync(req.body.password, salt);

            await User.updateOne({ _id: user._id }, { $set: { password: newPassword } });
            res.status(200).json({ code: 200, message: 'Your password has been changed' });
        });
    } catch (error) {
        next(error);
    }
};
