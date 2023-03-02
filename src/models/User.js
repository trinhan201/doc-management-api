import mongoose from 'mongoose';

const Schema = mongoose.Schema;

const UserSchema = new Schema(
    {
        userName: {
            type: String,
            required: true,
            trim: true,
            unique: true,
        },
        firstName: {
            type: String,
            required: true,
            trim: true,
        },
        lastName: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
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
            default: 'user',
        },
    },
    {
        timestamps: true,
    },
);

export default mongoose.model('User', UserSchema);
