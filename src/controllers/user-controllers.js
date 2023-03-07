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
        const updateProp = {
            userName: req.body.userName,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
        };
        if (req.user.role === 'admin') {
            try {
                const userUpdate = await User.findByIdAndUpdate(req.params.userId, updateProp, {
                    new: true,
                });
                res.status(200).json({ code: 200, message: 'This account has been updated' });
            } catch (error) {
                next(error);
            }
        } else {
            if (req.params.userId === req.user._id) {
                try {
                    const userUpdate = await User.findByIdAndUpdate(req.params.userId, updateProp, { new: true });
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
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        const currentUser = await User.findById(req.user._id);
        const isOldPassword = await bcrypt.compare(req.body.password, currentUser.password);
        if (!isOldPassword) {
            await User.findByIdAndUpdate({ _id: req.user._id }, { password: hash }, { new: true });
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
    } catch (error) {
        next(error);
    }
};
