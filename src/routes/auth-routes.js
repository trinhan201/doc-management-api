import { Router } from 'express';
import {
    signUpHandler,
    signInHandler,
    getCurrentUserController,
    refreshController,
} from '../controllers/auth-controllers.js';
import { verifyToken } from '../middlewares/verifyToken.js';

const router = Router();

// Create user
router.post('/signup', signUpHandler);

// Sign in
router.post('/signin', signInHandler);

// Refresh token route
router.post('/refresh/:id', refreshController);

// Get current user route
router.get('/current-user', verifyToken, getCurrentUserController);

export default router;
