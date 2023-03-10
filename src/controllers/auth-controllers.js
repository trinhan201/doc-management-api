import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import sendMail from '../utils/email.js';

// Generate access token
const generateAccessToken = (user) => {
    return jwt.sign({ _id: user._id, role: user.role }, process.env.ACCESS_SECRET, {
        expiresIn: '1500s',
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
        expiresIn: '300s',
    });
};

// Verify account controller
export const verifyHandler = async (req, res, next) => {
    try {
        const token = req.query.token;

        jwt.verify(token, process.env.VERIFY_EMAIL_SECRET, async (err, user) => {
            if (err) {
                return res.status(403).json({ code: 403, message: 'Token is not valid or it is expired' });
            }

            await User.updateOne({ _id: user._id }, { $set: { isVerified: true } });

            const currUser = await User.findById(user._id);
            // Send password to user
            const subject = 'Get Your Password';
            const html = `<p> Hello ${currUser.email}, This is your random password ${user.password}</p>
            <p>Let's change your password for security</p>
            `;
            sendMail(currUser.email, subject, html);
            res.status(200).send('Verified successfully, please check your inbox for password');
        });
    } catch (error) {
        next(error);
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
    const refreshToken = req.body.token;
    const currUser = await User.findById(req.user._id);
    let tokenArray = currUser.refreshTokens;
    tokenArray = tokenArray.filter((token) => token !== refreshToken);
    console.log(tokenArray);

    await User.findByIdAndUpdate(req.user._id, { $set: { refreshTokens: tokenArray } });
    res.status(200).json('You signed out successfully.');
};

// Forgot password controller
export const forgotPasswordHandler = async (req, res, next) => {
    try {
        const email = req.body.email;
        const userData = await User.findOne({ email: email });
        if (userData) {
            const subject = 'For Reset Password';
            const token = generateResetPasswordToken(userData);
            const html = `<p> Hello ${userData.userName}, Please copy the link and <a href="${process.env.CLIENT_URL}/api/v1/auth/reset-password?token=${token}"> reset your password</a>`;
            sendMail(userData.email, subject, html);
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
