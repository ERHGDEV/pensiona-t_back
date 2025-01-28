const jwt = require('jsonwebtoken')
const User = require('../models/user')
const config = require('./config')

const generateAccessToken = (user) => {
    return jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    )
}

const generateRefreshToken = (user) => {
    return jwt.sign(
        { userId: user._id },
        config.JWT_REFRESH_SECRET, 
        { expiresIn: '8h' } 
    )
}

const invalidatePreviousToken = async (userId) => {
    await User.findByIdAndUpdate(userId, { token: null })
}

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    invalidatePreviousToken
}