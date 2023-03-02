import { Router } from 'express';
import { signUpHandler } from '../controllers/auth-controllers.js';

const router = Router();

// Create user
router.post('/signup', signUpHandler);

export default router;
