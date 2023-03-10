import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import randomstring from 'randomstring';
import sendMail from '../utils/email.js';

// Generate verify email token
const generateVerifyEmailToken = (user, randomPass) => {
    return jwt.sign({ _id: user._id, password: randomPass }, process.env.VERIFY_EMAIL_SECRET, {
        expiresIn: '100s',
    });
};

// Create user controller
export const createUserHandler = async (req, res, next) => {
    try {
        const randomPass = randomstring.generate(7);
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(randomPass, salt);
        const newUser = new User({ ...req.body, password: hash });

        await newUser.save();
        const subject = 'Verify your account';
        const token = generateVerifyEmailToken(newUser, randomPass);
        const html = `<p>Click this <a href="${process.env.CLIENT_URL}/api/v1/auth/verify?token=${token}"> link</a> to verify your account`;
        sendMail(newUser.email, subject, html);
        res.status(200).json({ code: 200, message: 'Created successfully and verify mail has been sent' });
    } catch (err) {
        next(err);
    }
};

// Update user controller
export const updateUserHandler = async (req, res, next) => {
    try {
        const updateProps = {
            userName: req.body.userName,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
        };
        if (req.user.role === 'admin') {
            try {
                updateProps.role = req.body.role;
                const userUpdate = await User.findByIdAndUpdate(req.params.userId, updateProps, {
                    new: true,
                });
                res.status(200).json({ code: 200, message: 'This account has been updated' });
            } catch (error) {
                next(error);
            }
        } else {
            if (req.params.userId === req.user._id) {
                try {
                    const userUpdate = await User.findByIdAndUpdate(req.params.userId, updateProps, { new: true });
                    res.status(200).json({ code: 200, message: 'This account has been updated' });
                } catch (error) {
                    next(error);
                }
            } else {
                return res.status(403).json({
                    code: 403,
                    message: 'You can update only your account',
                });
            }
        }
    } catch (err) {
        next(err);
    }
};

// Delete user controller
export const deleteUserHandler = async (req, res, next) => {
    const user = await User.findById(req.params.userId);
    if (user.role === 'admin') {
        res.status(403).json({
            code: 403,
            message: 'You cannot delete admin account',
        });
    } else {
        try {
            await User.findOneAndDelete({ _id: req.params.userId });
            res.status(200).json({
                code: 200,
                message: 'User account has been deleted',
            });
        } catch (error) {
            next(error);
        }
    }
};

// Change password controller
export const changePasswordHandler = async (req, res, next) => {
    try {
        const currentUser = await User.findById(req.user._id);
        // Old password from frontend
        const oldPassword = req.body.oldPassword;
        // New password from frontend
        const salt = bcrypt.genSaltSync(10);
        const newPassword = bcrypt.hashSync(req.body.newPassword, salt);
        // Check old password from frontend is the same of password in db
        const isCorrect = await bcrypt.compare(oldPassword, currentUser.password);
        // Check new password conflict with password in db
        const isConflict = await bcrypt.compare(req.body.newPassword, currentUser.password);

        if (!isCorrect) {
            res.status(400).json({
                code: 400,
                message: 'Old password is wrong and please try again',
            });
        } else {
            if (!isConflict) {
                await User.findByIdAndUpdate({ _id: req.user._id }, { password: newPassword }, { new: true });
                res.status(200).json({
                    code: 200,
                    message: 'Change password successfully',
                });
            } else {
                res.status(400).json({
                    code: 400,
                    message: 'Password conflict',
                });
            }
        }
    } catch (error) {
        next(error);
    }
};
