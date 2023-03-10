import { Router } from 'express';
import {
    signInHandler,
    getCurrentUserHandler,
    refreshHandler,
    signOutHandler,
    forgotPasswordHandler,
    resetPasswordHandler,
    verifyHandler,
} from '../controllers/auth-controllers.js';
import { verifyToken } from '../middlewares/verifyToken.js';

const router = Router();

// Sign in
router.post('/signin', signInHandler);

// Refresh token route
router.post('/refresh/:userId', refreshHandler);

// Sign out route
router.post('/signout', verifyToken, signOutHandler);

// Get current user route
router.get('/current-user', verifyToken, getCurrentUserHandler);

// Forgot password route
router.post('/forgot-password', forgotPasswordHandler);

// Reset password route
router.post('/reset-password', resetPasswordHandler);

// Veify account route
router.get('/verify', verifyHandler);

export default router;
