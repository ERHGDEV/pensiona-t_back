const jwt = require('jsonwebtoken')
const User = require('../models/user')
const logger = require('./logger')
const config = require('./config')
const rateLimit = require('express-rate-limit')

const requestLogger = (request, response, next) => {
    logger.info('Method:', request.method)
    logger.info('Path:  ', request.path)
    logger.info('Body:  ', request.body)
    logger.info('---')
    next()
}

const unknownEndpoint = (request, response) => {
    response.status(404).send({ error: 'unknown endpoint' })
}

const errorHandler = (error, request, response, next) => {
    logger.error(error.message)

    if (error.name === 'CastError') {
        return response.status(400).send({ error: 'malformatted id' })
    } else if (error.name === 'ValidationError') {
        return response.status(400).json({ error: error.message })
    } else if (error.name === 'JsonWebTokenError') {
        return response.status(401).json({
            error: 'invalid token'
        })
    }

    next(error)
}

const checkAndUpdateUserStatus = async (user) => {
    const currentDate = new Date()
    if (!user.subscription) {
        user.subscription = 'free'
        await user.save()
    }

    if (user.subscription === 'free') {
      return user
    }

    if (currentDate > user.expiration) {
      user.subscription = 'free'
      await user.save()
    }
    return user
}

const verifyToken = async (request, response, next) => {
    const token = request.headers['authorization']?.split(' ')[1]

    if (!token) {
        return response.status(401).json({ 
            success: false, 
            message: 'No se proporcionó el token en el encabezado Authorization' 
        })
    }

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET)
        const user = await User.findById(decoded.userId)

        if (!user) {
            return response.status(401).json({ 
                success: false, 
                message: 'Usuario no encontrado. Por favor, inicie sesión nuevamente' 
            })
        }

        if (user.token !== token) {
            return response.status(401).json({ 
                success: false, 
                message: 'Token inválido. Por favor, inicie sesión nuevamente' 
            })
        }

        request.user = {
            id: user._id,
            email: user.email,
            role: user.role
        }

        next()
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return response.status(401).json({ 
                success: false, 
                message: 'Token expirado. Por favor, inicie sesión nuevamente' 
            })
        } else {
            logger.error('Error durante la verificación del token: ', error)
            return response.status(401).json({ 
                success: false, 
                message: 'No autorizado' 
            })
        }
    }
}

const verifyAdmin = (request, response, next) => {
    try {
        if (request.user.role !== 'admin') {
            return response.status(403).json({ success: false, message: 'No autorizado' })
        }
        next()
    } catch (error) {
        logger.error('Error durante la verificación del rol administrador: ', error)
        return response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
}

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: {
        success: false,
        message: 'Has superado el límite de solicitudes. Intente nuevamente en 15 minutos'
    }
})

module.exports = {
    requestLogger,
    unknownEndpoint,
    errorHandler,
    checkAndUpdateUserStatus,
    verifyToken,
    verifyAdmin,
    limiter
}