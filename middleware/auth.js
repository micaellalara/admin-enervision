// auth.js
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET || "4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd";

function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        
        req.user = decoded.user; 
        next();
    } catch (error) {
        return res.redirect('/login'); 
    }
}

module.exports = authenticateToken;
