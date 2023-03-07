import { Router } from 'express';
import {
    createUserHandler,
    updateUserHandler,
    deleteUserHandler,
    changePasswordHandler,
} from '../controllers/user-controllers.js';
import { isAdmin, isManager, isEmployee } from '../helpers/role.js';
import { verifyToken } from '../middlewares/verifyToken.js';

const router = Router();

// Create user route
router.post('/create-user', verifyToken, isAdmin, createUserHandler);

// Update user route
router.put('/update-user/:userId', verifyToken, isEmployee, updateUserHandler);

// Delete user route
router.delete('/delete-user/:userId', verifyToken, isAdmin, deleteUserHandler);

// Change password route
router.patch('/change-password', verifyToken, isEmployee, changePasswordHandler);

export default router;
