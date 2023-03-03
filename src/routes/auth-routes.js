import { Router } from 'express';
import { signUpHandler, signInHandler } from '../controllers/auth-controllers.js';

const router = Router();

// Create user
router.post('/signup', signUpHandler);

// Sign in
router.post('/signin', signInHandler);

export default router;
