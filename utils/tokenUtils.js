const jwt = require('jsonwebtoken')
const User = require('../models/user')
const config = require('./config')

const generateUniqueToken = (user) => {
    return jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    )
}

const invalidatePreviousToken = async (userId) => {
    await User.findByIdAndUpdate(userId, { token: null })
}

module.exports = {
    generateUniqueToken,
    invalidatePreviousToken
}