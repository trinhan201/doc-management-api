import { Router } from 'express';
import {
    signUpHandler,
    signInHandler,
    getCurrentUserHandler,
    refreshHandler,
    signOutHandler,
} from '../controllers/auth-controllers.js';
import { verifyToken } from '../middlewares/verifyToken.js';

const router = Router();

// Create user
router.post('/signup', signUpHandler);

// Sign in
router.post('/signin', signInHandler);

// Refresh token route
router.post('/refresh/:userId', refreshHandler);

// Sign out route
router.post('/signout', verifyToken, signOutHandler);

// Get current user route
router.get('/current-user', verifyToken, getCurrentUserHandler);

export default router;
