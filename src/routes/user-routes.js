import { Router } from 'express';
import { createUserHandler } from '../controllers/user-controllers.js';
import { isAdmin, isManager, isEmployee } from '../helpers/role.js';
import { verifyToken } from '../middlewares/verifyToken.js';

const router = Router();

// Create user
router.post('/create-user', verifyToken, isAdmin, createUserHandler);

export default router;
