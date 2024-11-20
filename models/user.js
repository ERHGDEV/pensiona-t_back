const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    expiration: { type: Date, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    created: { type: Date, default: Date.now },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    token: { type: String, default: null },
    verified: { type: Boolean, default: false },
    verificationToken: { type: String, default: null },
    recoveryToken: { type: String, default: null },
    calculosRealizados: { type: Number, default: 0 },
    reportesGenerados: { type: Number, default: 0 },
    aforesConsultadas: { type: Number, default: 0 }
})

module.exports = mongoose.model('User', userSchema)