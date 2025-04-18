const publicRouter = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const sgMail = require('@sendgrid/mail')
const User = require('../models/user')
const LoginHistory = require('../models/loginHistory')
const config = require('../utils/config')
const logger = require('../utils/logger')
const { createVerificationEmail, createRecoveryEmail } = require('../utils/emailTemplates')
const { checkAndUpdateUserStatus, limiter } = require('../utils/middleware')
const { generateAccessToken, generateRefreshToken, invalidatePreviousToken } = require('../utils/tokenUtils')

sgMail.setApiKey(config.SENDGRID_API_KEY)

// Redirige a la URL del frontend
publicRouter.get('/', (request, response) => {
    response.redirect(config.URL_FRONTEND)
})

// Inicia sesión del usuario, genera token y guarda en BD
publicRouter.post('/api/login', limiter, async (request, response) => {
    const { email, password } = request.body
  
    try {
        let user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } })

        if (!user) {
            return response.json({ success: false, message: 'Usuario incorrecto' })
        }

        if (!user.verified) {
            return response.json({ success: false, message: 'Cuenta no verificada, revisa tu bandeja de entrada' })
        }
  
        if (user.status === 'inactive') {
            return response.json({ success: false, message: 'Usuario inactivo' })
        }
  
        const isMatch = await bcrypt.compare(password, user.password)
  
        if (!isMatch) {
            return response.json({ success: false, message: 'Contraseña incorrecta' })
        }

        if (user.token) {
            try {
                const decoded = jwt.verify(user.token, config.JWT_SECRET)
                if (decoded) {
                    return response.json({ success: false, message: 'Ya tienes una sesión activa' })
                }
            } catch (error) {
                logger.info(`Token anterior inválido o expirado para el usuario ${user.email}`)
                // Permitimos iniciar sesión normalmente
            }
        }

        user = await checkAndUpdateUserStatus(user)
  
        const token = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)
  
        user.token = token
        user.refreshToken = refreshToken
        await user.save()

        if (user.email !== 'contacto@pensiona-t.com') {
            await LoginHistory.create({
                email: user.email,
                role: user.role,
                ipAddress: request.ip
            })
        }
            response.json({ 
                success: true, 
                email: user.email, 
                role: user.role, 
                token, 
                refreshToken 
            })
    } catch (error) {
        logger.error('Error durante el inicio de sesión: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Renueva el token de acceso del usuario
publicRouter.post('/api/refresh-token', async (request, response) => {
    const { refreshToken } = request.body

    if (!refreshToken) {
        return response.status(400).json({ success: false, message: 'Refresh token no proporcionado' })
    }

    try {
        const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET)
        const user = await User.findById(decoded.userId)

        if (!user || user.refreshToken !== refreshToken) {
            return response.status(403).json({ success: false, message: 'Refresh token inválido' })
        }

        const newAccessToken = generateAccessToken(user)
        user.token = newAccessToken
        await user.save()
        
        response.json({
            success: true,
            accessToken: newAccessToken
        })
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return response.status(403).json({ success: false, message: 'Refresh token expirado' })
        } else {
            logger.error('Error durante la renovación del token: ', error)
            return response.status(500).json({ success: false, message: 'Error en el servidor' })
        }
    }
})

// Registra un nuevo usuario, envía correo de verificación y guarda token de verificación
publicRouter.post('/api/register', limiter, async (request, response) => {
    const { name, email, password } = request.body

    try {
        const existingUser = await User.findOne({ email })
        
        if (existingUser) {
            return response.status(400).json({ success: false, message: 'Correo electrónico ya registrado' })
        }
        
        const hashedPassword = await bcrypt.hash(password, 10)

        const expiration = new Date()
        const verificationToken = jwt.sign({ email }, config.JWT_SECRET, { expiresIn: '7d' })

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            expiration,
            verificationToken
        })

        await newUser.save()

        const verificationUrl = `${config.URL_FRONTEND}/verify?token=${verificationToken}`
        const verificationEmail = createVerificationEmail(name, email, verificationUrl)
        await sgMail.send(verificationEmail)

        response.json({ success: true, message: 'Usuario registrado, revisa tu bandeja de entrada' })
    } catch (error) {
        logger.error('Error during registration: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Envía correo de recuperación de contraseña y guarda token de recuperación
publicRouter.post('/api/recovery', limiter, async (request, response) => {
    const { email } = request.body

    try {
        const user = await User.findOne({ email: email })
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        const recoveryToken = jwt.sign({ email }, config.JWT_SECRET, { expiresIn: '2d' })
        user.recoveryToken = recoveryToken
        await user.save()

        const recoveryUrl = `${config.URL_FRONTEND}/recovery?token=${recoveryToken}`
        const recoveryEmail = createRecoveryEmail(user.name, email, recoveryUrl)
        await sgMail.send(recoveryEmail)

        response.json({ success: true, message: 'Correo de recuperación enviado, revisa tu bandeja de entrada' })
    } catch (error) {
        logger.error('Error during recovery:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Valida el token de recuperación de contraseña
publicRouter.get('/api/recovery', limiter, async (request, response) => {
    const { token } = request.query

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET)
        const user = await User.findOne({ email: decoded.email })

        if (!user) {
            return response.status(404).json({ success: false, message: 'Usuario no encontrado' })
        }

        if (user.recoveryToken !== token) {
            return response.status(400).json({ success: false, message: 'Token de recuperación inválido' })
        }

        return response.status(200).json({ success: true, message: 'Token de recuperación válido' })
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            const decoded = jwt.decode(token)
            if (decoded && decoded.email) {
                const user = await User.findOne({ email: decoded.email })
                if (user) {
                    user.recoveryToken = null
                    await user.save()
                }
            }
            return response.status(400).json({ success: false, message: 'Token expirado, solicita nuevamente la recuperación de contraseña' })
        }

        logger.error('Error during validation:', error)
        return response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Actualiza la contraseña del usuario con el token de recuperación
publicRouter.post('/api/reset-password', limiter, async (request, response) => {
    const { token, newPassword } = request.body

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET)
        const user = await User.findOne({ email: decoded.email })

        if (!user) {
            return response.status(404).json({ success: false, message: 'Usuario no encontrado' })
        }

        if (user.recoveryToken !== token) {
            return response.status(400).json({ success: false, message: 'Token de recuperación inválido' })
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        user.password = hashedPassword
        user.recoveryToken = null
        await user.save()

        response.json({ success: true, message: 'Contraseña actualizada exitosamente' })
    } catch (error) {
        logger.error('Error during password reset:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Verifica el token de verificación y actualiza el estado del usuario
publicRouter.get('/api/verify', limiter, async (request, response) => {
    const { token } = request.query

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET)
        const user = await User.findOne({ email: decoded.email })

        if (!user) {
            return response.status(404).json({ success: false, message: 'Usuario no encontrado' })
        } else if (user.verified) {
            return response.status(200).json({ success: true, message: 'Usuario ya verificado' })
        } else if (user.verificationToken !== token) {
            return response.status(400).json({ success: false, message: 'Token de verificación inválido' })
        } else {
            user.verified = true
            user.verificationToken = null
            await user.save()
            return response.status(200).json({ success: true, message: 'Usuario verificado exitosamente' })
        }
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            const decoded = jwt.decode(token)
            if (decoded && decoded.email) {
                const user = await User.findOne({ email: decoded.email })

                if (user && !user.verified) {
                    await User.deleteOne({ email: decoded.email })
                    return response.status(410).json({ success: false, message: 'Token expirado. Debe registrarse nuevamente' })
                }
            }
        } else if (error instanceof jwt.JsonWebTokenError) {
            return response.status(400).json({ success: false, message: 'Token de verificación inválido' })
        }

        logger.error('Error during verification:', error)
        return response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

module.exports = publicRouter