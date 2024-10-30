const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    numeroConsar: { type: Number, required: true },
    firstname: { type: String, required: true },
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
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    token: { type: String, default: null }
})

userSchema.methods.clearToken = function() {
    this.token = null;
    return this.save();
}

userSchema.methods.setToken = function(token) {
    this.token = token;
    this.isLoggedIn = true;
    return this.save();
}

userSchema.methods.verifyToken = function(token) {
    return this.token === token;
}

module.exports = mongoose.model('User', userSchema)