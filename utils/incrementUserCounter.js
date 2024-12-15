const User = require('../models/user')
const logger = require('./logger')

const incrementUserCounter = async (userId, fieldName, incrementBy = 1) => {
    try {
        const user = await User.findById(userId)
        if (!user) {
            return { success: false, message: 'Usuario no encontrado' }
        }

        user[fieldName] = (user[fieldName] || 0) + incrementBy
        await user.save()

        return { success: true, message: `Contador de ${fieldName} incrementado` }
    } catch (error) {
        logger.error(`Error al incrementar contador de ${fieldName} para usuario ${userId}: ${error}`)
        throw new Error('Error al incrementar contador')
    }
}

module.exports = { incrementUserCounter }