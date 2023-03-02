import { createUser } from '../services/auth-services.js';

export const signUpHandler = async (req, res, next) => {
    try {
        await createUser(req, res);
        res.status(200).send('User has been created!');
    } catch (err) {
        next(err);
    }
};
