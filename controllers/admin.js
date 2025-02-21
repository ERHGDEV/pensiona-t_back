const adminRouter = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const sgMail = require('@sendgrid/mail')
const { startOfDay, endOfDay, parseISO } = require('date-fns')
const User = require('../models/user')
const Preference = require('../models/preference')
const Payment = require('../models/payment')
const Values = require('../models/values')
const LoginHistory = require('../models/loginHistory')
const config = require('../utils/config')
const logger = require('../utils/logger')
const { createVerificationEmail, createGeneralEmail } = require('../utils/emailTemplates')
const { verifyToken, verifyAdmin } = require('../utils/middleware')

sgMail.setApiKey(config.SENDGRID_API_KEY)

// Obtiene lista de usuarios para el administrador, excluyendo al administrador y campo de contraseña
adminRouter.get('/api/admin', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const users = await User.find({ role: { $ne: 'admin' } }).select('-password')

        // Obtener el último inicio de sesión de cada usuario
        const loginHistories = await LoginHistory.aggregate([
            { $sort: { loginDate: -1 } },
            {
                $group: {
                    _id: "$email",
                    lastLogin: { $first: "$loginDate" },
                },
            },
        ])

        const loginMap = loginHistories.reduce((map, history) => {
            map[history._id] = history.lastLogin
            return map
        }, {})

        // Obtener los correos electrónicos de los usuarios
        const emails = users.map(user => user.email)
        
        // Buscar preferencias asociadas a los usuarios
        const preferences = await Preference.find({ email: { $in: emails } })
        const externalReferences = preferences.reduce((map, pref) => {
            map[pref.external_reference] = pref
            return map
        }, {})

        // Buscar pagos relacionados con las external_references
        const payments = await Payment.find({ external_reference: { $in: Object.keys(externalReferences) } })

        // Mapear pagos con su respectivo usuario
        const paymentHistory = payments.map(payment => ({
            user: users.find(user => user.email === externalReferences[payment.external_reference]?.email)?.name || 'Desconocido',
            email: externalReferences[payment.external_reference]?.email,
            amount: payment.amount,
            date: payment.transactionDate,
            status: payment.status,
            external_reference: payment.external_reference,
            id: payment._id
        }))

        // Mapear preferencias con status basado en pagos aprobados
        const preferencesWithStatus = preferences.map(pref => {
            const hasApprovedPayment = payments.some(payment =>
                payment.external_reference === pref.external_reference && payment.status === "approved"
            )
            return {
                id: pref._id,
                email: pref.email,
                date_created: pref.date_created,
                total_amount: pref.total_amount,
                status: hasApprovedPayment ? "approved" : "pending"
            }
        })

        const usersWithLastLogin = users.map((user) => ({
            ...user.toObject(),
            lastLogin: loginMap[user.email] || null,
        }))

        response.json({ users: usersWithLastLogin, payments: paymentHistory, preferences: preferencesWithStatus })
    } catch (error) {
        logger.error('Error fetching users and payments: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Crea un nuevo usuario, envía correo de verificación y guarda token de verificación
adminRouter.post('/api/admin/users', verifyToken, verifyAdmin, async (request, response) => {
    const { name, email, password, role } = request.body

    try {
        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return response.json({ success: false, message: 'Correo electrónico ya registrado' })
        }
        
        const hashedPassword = await bcrypt.hash(password, 10)

        const expiration = new Date()
        const verificationToken = jwt.sign({ email }, config.JWT_SECRET, { expiresIn: '7d' })

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role,
            expiration,
            verificationToken
        })

        await newUser.save()
        const verificationUrl = `${config.URL_FRONTEND}/verify?token=${verificationToken}`
        const verificationEmail = createVerificationEmail(name, email, verificationUrl)
        await sgMail.send(verificationEmail)

        response.json({ success: true, message: 'Usuario creado exitosamente' })
    } catch (error) {
        logger.error('Error during user creation: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Actualiza un usuario por ID, excluyendo campo de contraseña
adminRouter.put('/api/admin/users/:id', verifyToken, verifyAdmin, async (request, response) => {
    const { id } = request.params
    const { name, email, role, expiration, status } = request.body

    try {
        const user = await User.findById(id)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        user.name = name
        user.email = email
        user.role = role
        user.expiration = expiration
        user.status = status

        await user.save()

        response.json({ success: true, message: 'Usuario actualizado exitosamente' })
    } catch (error) {
        logger.error('Error during user update: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Elimina un usuario por ID
adminRouter.delete('/api/admin/users/:id', verifyToken, verifyAdmin, async (request, response) => {
    const { id } = request.params

    try {
        const user = await User.findById(id)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        await user.deleteOne()

        response.json({ success: true, message: 'Usuario eliminado exitosamente' })
    } catch (error) {
        logger.error('Error during user deletion: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Obtiene el historial de inicio de sesión por día de un rango de fechas
adminRouter.get('/api/admin/login-history', verifyToken, verifyAdmin, async (request, response) => {
    const { start, end } = request.query

    try {
        const startDate = startOfDay(parseISO(start))
        const endDate = endOfDay(parseISO(end))
        const timeZoneOffset = -6

        const loginData = await LoginHistory.aggregate([
            {
                $match: {
                    loginDate: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $addFields: {
                    adjustedDate: {
                        $dateAdd: {
                            startDate: "$loginDate",
                            unit: "hour",
                            amount: timeZoneOffset
                        }
                    }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$adjustedDate" }
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ])

        const formattedData = loginData.map(item => ({
            date: item._id,
            count: item.count
        }))

        response.json(formattedData)
    } catch (error) {
        logger.error('Error fetching login activity:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Envía correo masivo a todos los usuarios
adminRouter.post('/api/admin/send-bulk-email', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const { subject, body } = request.body

        if (!subject || !body) {
            return response.json({ success: false, message: 'Asunto y mensaje requeridos'})
        }

        const users = await User.find({}, 'email')
        const emails = users.map(user => user.email)

        const msg = createGeneralEmail(subject, body)
        msg.to = emails
        
        await sgMail.sendMultiple(msg)

        logger.info(`Bulk email sent successfully to ${emails.length} users`)
        response.json({ success: true, message: `Email enviado a ${emails.length} usuarios` }) 
    } catch (error) {
        logger.error('Error sending bulk email:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Obtiene los valores de salario mínimo y UMA
adminRouter.get('/api/admin/values', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const values = await Values.findOne()
        if (!values) {
            return response.json({ success: false, message: 'No se encontraron valores' })
        }
        response.json({ success: true, salarioMinimo: values.salarioMinimo, uma: values.uma })
    } catch (error) {
        logger.error('Error fetching values: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Actualiza los valores de salario mínimo y UMA
adminRouter.put('/api/admin/values', verifyToken, verifyAdmin, async (request, response) => {
    const { salarioMinimo, uma } = request.body

    try {
        let values = await Values.findOne()
        if (!values) {
            values = new Values({ salarioMinimo, uma })
        } else {
            values.salarioMinimo = salarioMinimo
            values.uma = uma
        }
        await values.save()
        response.json({ success: true, message: 'Valores actualizados exitosamente' })
    } catch (error) {
        logger.error('Error updating values: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

module.exports = adminRouter