export const isAdmin = (req, res, next) => {
    let role = req.user.role;
    if (role === 'admin') {
        next();
    } else {
        return res.status(401).json({
            code: 401,
            message: 'NOT PERMISSION',
        });
    }
};

export const isManager = (req, res, next) => {
    let role = req.user.role;
    if (role === 'admin' || role === 'manager') {
        next();
    } else {
        return res.status(401).json({
            code: 401,
            message: 'NOT PERMISSION',
        });
    }
};

export const isEmployee = (req, res, next) => {
    let role = req.user.role;
    if (role === 'admin' || role === 'manager' || role === 'employee') {
        next();
    } else {
        return res.status(401).json({
            code: 401,
            message: 'NOT PERMISSION',
        });
    }
};
