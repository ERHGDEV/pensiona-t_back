const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    secretQuestion: {
        type: String,
        required: true
    },
    secretAnswer: {
        type: String,
        required: true
    },
    expiration: { type: Date, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    created: { type: Date, default: Date.now },
    isLoggedIn: { type: Boolean, default: false },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' }
})

module.exports = mongoose.model('User', userSchema)