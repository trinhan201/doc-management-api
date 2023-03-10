import mongoose from 'mongoose';

const Schema = mongoose.Schema;

const UserSchema = new Schema(
    {
        userName: {
            type: String,
            required: true,
            minlength: 2,
            maxlength: 100,
            trim: true,
            unique: true,
        },
        firstName: {
            type: String,
            required: true,
            minlength: 2,
            maxlength: 100,
            trim: true,
        },
        lastName: {
            type: String,
            required: true,
            minlength: 2,
            maxlength: 100,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address'],
            trim: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
            trim: true,
        },
        role: {
            type: String,
            default: 'employee',
        },
        refreshTokens: {
            type: Array,
        },
        isVerified: {
            type: Boolean,
            default: false,
        },
    },
    {
        timestamps: true,
    },
);

export default mongoose.model('User', UserSchema);
