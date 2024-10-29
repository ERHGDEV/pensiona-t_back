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
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    token: { type: String, default: null }
})

// Método para limpiar el token del usuario
userSchema.methods.clearToken = function() {
    this.token = null;
    return this.save();
}

// Método para establecer un nuevo token
userSchema.methods.setToken = function(token) {
    this.token = token;
    this.isLoggedIn = true;
    return this.save();
}

// Método para verificar si el token del usuario coincide
userSchema.methods.verifyToken = function(token) {
    return this.token === token;
}

module.exports = mongoose.model('User', userSchema)