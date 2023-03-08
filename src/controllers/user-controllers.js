import User from '../models/User.js';
import bcrypt from 'bcryptjs';

// Create user controller
export const createUserHandler = async (req, res, next) => {
    try {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        const newUser = new User({ ...req.body, password: hash });

        await newUser.save();
        res.status(200).json({ code: 200, message: 'User has been created!' });
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
