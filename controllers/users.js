const usersRouter = require('express').Router()
const axios = require('axios')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const sgMail = require('@sendgrid/mail')
const { startOfDay, endOfDay, parseISO } = require('date-fns')
const User = require('../models/user')
const Values = require('../models/values')
const LoginHistory = require('../models/loginHistory')
const config = require('../utils/config')
const logger = require('../utils/logger')
const { generarEmailAleatorio } = require('../utils/emailUtils')
const { consultarAfore } = require('../utils/consultarAfore')
const { incrementUserCounter } = require('../utils/incrementUserCounter')
const { createVerificationEmail, createRecoveryEmail, createGeneralEmail } = require('../utils/emailTemplates')
const { checkAndUpdateUserStatus, verifyToken, verifyAdmin, limiter } = require('../utils/middleware')
const { generateUniqueToken, invalidatePreviousToken } = require('../utils/tokenUtils')

sgMail.setApiKey(config.SENDGRID_API_KEY)

// Redirige a la URL del frontend
usersRouter.get('/', (request, response) => {
    response.redirect(config.URL_FRONTEND)
})

// Inicia sesión del usuario, genera token y guarda en BD
usersRouter.post('/api/login', limiter, async (request, response) => {
    const { email, password } = request.body
  
    try {
        let user = await User.findOne({ email })
  
        if (!user) {
            return response.json({ success: false, message: 'Usuario incorrecto' })
        }

        if (!user.verified) {
            return response.json({ success: false, message: 'Cuenta no verificada, revisa tu bandeja de entrada' })
        }
  
        /* user = await checkAndUpdateUserStatus(user) */
  
        if (user.status === 'inactive') {
            return response.json({ success: false, message: 'Usuario inactivo' })
        }
  
        const isMatch = await bcrypt.compare(password, user.password)
  
        if (!isMatch) {
            return response.json({ success: false, message: 'Contraseña incorrecta' })
        }
  
        if (user.token) {
            await invalidatePreviousToken(user._id)
        }
  
        const token = generateUniqueToken(user)
  
        user.token = token
        await user.save()

        if (user.email !== 'contacto@pensiona-t.com' &&
            user.email !== 'erhgdev@gmail.com' &&
            user.email !== 'erickrhernandezg@gmail.com' &&
            user.email !== 'ericardohernandezg@gmail.com'    
        ) {
            await LoginHistory.create({
                email: user.email,
                role: user.role,
                ipAddress: request.ip
            })
        }
  
            response.json({ success: true, email: user.email, role: user.role, token })
    } catch (error) {
        logger.error('Error durante el inicio de sesión: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Cierra la sesión del usuario, invalida el token actual
usersRouter.post('/api/logout', verifyToken, async (request, response) => {
    try {
        await invalidatePreviousToken(request.userId)
        response.json({ success: true, message: 'Sesión cerrada' })
    } catch (error) {
        logger.error('Error durante el cierre de sesión: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Obtiene lista de usuarios para el administrador, excluyendo al administrador y campo de contraseña
usersRouter.get('/api/admin', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const users = await User.find({ role: { $ne: 'admin' } }).select('-password')

        const loginHistories = await LoginHistory.aggregate([
            { $sort: { loginDate: -1 } }, // Ordenar por fecha de inicio de sesión descendente
            {
                $group: {
                    _id: "$email",
                    lastLogin: { $first: "$loginDate" }, // Obtener el último inicio de sesión
                },
            },
        ])

        const loginMap = loginHistories.reduce((map, history) => {
            map[history._id] = history.lastLogin
            return map
        }, {})

        const usersWithLastLogin = users.map((user) => ({
            ...user.toObject(),
            lastLogin: loginMap[user.email] || null, // Agregar el último inicio de sesión o null si no existe
        }))

        response.json(usersWithLastLogin)
    } catch (error) {
        logger.error('Error fetching users: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})


// Crea un nuevo usuario, envía correo de verificación y guarda token de verificación
usersRouter.post('/api/admin/users', verifyToken, verifyAdmin, async (request, response) => {
    const { name, email, password, role } = request.body

    try {
        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return response.json({ success: false, message: 'Correo electrónico ya registrado' })
        }
        
        const hashedPassword = await bcrypt.hash(password, 10)

        const currentDate = new Date()
        const expiration = new Date(currentDate.setDate(currentDate.getDate() + 30))
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
usersRouter.put('/api/admin/users/:id', verifyToken, verifyAdmin, async (request, response) => {
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
usersRouter.delete('/api/admin/users/:id', verifyToken, verifyAdmin, async (request, response) => {
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
usersRouter.get('/api/admin/login-history', verifyToken, verifyAdmin, async (request, response) => {
    const { start, end } = request.query;

    try {
        const startDate = startOfDay(parseISO(start));
        const endDate = endOfDay(parseISO(end));
        const timeZoneOffset = -6;

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
        ]);

        const formattedData = loginData.map(item => ({
            date: item._id,
            count: item.count
        }));

        response.json(formattedData);
    } catch (error) {
        logger.error('Error fetching login activity:', error);
        response.status(500).json({ success: false, message: 'Error en el servidor' });
    }
});

// Envía correo masivo a todos los usuarios
usersRouter.post('/api/admin/send-bulk-email', verifyToken, verifyAdmin, async (request, response) => {
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
usersRouter.get('/api/admin/values', verifyToken, verifyAdmin, async (request, response) => {
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
usersRouter.put('/api/admin/values', verifyToken, verifyAdmin, async (request, response) => {
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

// Obtiene los valores de salario mínimo y UMA
usersRouter.get('/api/values', async (request, response) => {
    try {
        const values = await Values.findOne()
        if (!values) {
            return response.status(404).json({ success: false, message: 'No se encontraron valores' })
        }
        response.json({ success: true, salarioMinimo: values.salarioMinimo, uma: values.uma })
    } catch (error) {
        logger.error('Error fetching values: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Obtiene el usuario actual
usersRouter.get('/api/user', verifyToken, async (request, response) => {
    try { 
        const user = await User.findById(request.userId)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        response.json({
            name: user.name,
            email: user.email,
            role: user.role,
            expiration: user.expiration,
            status: user.status,
            created: user.created,
            profileImage: user.profileImage || null,
            calculosRealizados: user.calculosRealizados || 0,
            reportesGenerados: user.reportesGenerados || 0,
            aforesConsultadas: user.aforesConsultadas || 0,
            pdfAnalizados: user.pdfAnalizados || 0
        })
    } catch (error) {
        logger.error('Error during user fetch: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Actualiza el usuario actual, por el momento el name  
usersRouter.put('/api/user/update', verifyToken, async (request, response) => {
    try {
        const { name } = request.body

        if (!name) {
            return response.status(400).json({ success: false, message: 'Nombre requerido' })
        }

        const user = await User.findById(request.userId)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        user.name = name
        await user.save()

        response.json({ success: true, message: 'Usuario actualizado exitosamente' })
    } catch (error) {
        logger.error('Error during user update: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Incrementa el contador de cálculos realizados
usersRouter.put('/api/user/increment-calculos', verifyToken, async (request, response) => {
    try {
        const result = await incrementUserCounter(request.userId, 'calculosRealizados')
        response.json(result)
    } catch (error) {
        response.status(500).json({ success: false, message: error.message })
    }
})

// Incrementa el contador de reportes generados
usersRouter.put('/api/user/increment-reportes', verifyToken, async (request, response) => {
    try {
        const result = await incrementUserCounter(request.userId, 'reportesGenerados')
        response.json(result)
    } catch (error) {
        response.status(500).json({ success: false, message: error.message })
    }
})

// Incrementa el contador de PDFs analizados
usersRouter.put('/api/user/increment-pdf', verifyToken, async (request, response) => {
    try {
        const result = await incrementUserCounter(request.userId, 'pdfAnalizados')
        response.json(result)
    } catch (error) {
        response.status(500).json({ success: false, message: error.message })
    }
})

// Endpoint para hacer la solicitud de consulta de AFORE por NSS
usersRouter.post('/api/afore-info-nss', verifyToken, async (req, res) => {
  const { nss } = req.body;

  if (!nss) {
    return res.status(400).json({
      error: 'El campo nss es obligatorio.',
    })
  }

  try {
    const response = await consultarAfore('nss', nss, req.userId)
    res.status(response.status).json(response.data)
  } catch (error) {
    logger.error('Error al hacer la solicitud:', error.message)
    res.status(error.response?.status || 500).json({
      error: 'Error al obtener los datos de AFORE.',
      detalles: error.response?.data || error.message,
    })
  }
})

// Endpoint para hacer la solicitud de consulta de AFORE por CURP
usersRouter.post('/api/afore-info-curp', verifyToken, async (req, res) => {
  const { curp } = req.body

  if (!curp) {
    return res.status(400).json({
      error: 'El campo CURP es obligatorio.',
    })
  }

  try {
    const response = await consultarAfore('curp', curp, req.userId)
    res.status(response.status).json(response.data)
  } catch (error) {
    logger.error('Error al hacer la solicitud:', error.message)
    res.status(error.response?.status || 500).json({
      error: 'Error al obtener los datos de AFORE.',
      detalles: error.response?.data || error.message,
    })
  }
})

// Consulta bulk de afore
usersRouter.post('/api/batch-afore-info', verifyToken, async (req, res) => {
  const { nssArray } = req.body

  if (!Array.isArray(nssArray) || nssArray.length === 0 || nssArray.length > 100) {
    return res.status(400).json({
      error: 'El array de NSS debe contener entre 1 y 100 elementos.',
    })
  }

  const results = []
  let successfulQueries = 0

  for (const nss of nssArray) {
    const nssString = nss.toString();
    if (nssString.length !== 11 || !/^\d+$/.test(nssString)) {
      results.push({ nss, afore: 'Formato inválido' })
      continue
    }

    const emailAleatorio = generarEmailAleatorio()
    const url = `https://api.esar.io/sartoken/externos/web/localizatuafore/afore/${emailAleatorio}/nss/${nssString}`

    try {
      const response = await axios.get(url, {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          Origin: 'https://www.aforeweb.com.mx',
          Referer: 'https://www.aforeweb.com.mx/',
        },
      })

      if (response.data.claveAfore !== null) {
        results.push({ nss, afore: response.data.claveAfore })
        successfulQueries++
      } else {
        results.push({ nss, afore: 'Intenta de nuevo mañana' })
      }
    } catch (error) {
      logger.error(`Error al consultar AFORE para NSS ${nss}:`, error.message)
      results.push({ nss, afore: 'Error en la consulta' })
    }

    await new Promise(resolve => setTimeout(resolve, 100))
  }

  try {
    const user = await User.findById(req.userId)
    if (user) {
      user.aforesConsultadas = (user.aforesConsultadas || 0) + successfulQueries
      await user.save()
      logger.info(`Usuario ${req.userId} consultó ${successfulQueries} AFOREs exitosamente`)
    } else {
      logger.error('Usuario no encontrado:', req.userId)
    }
  } catch (error) {
    logger.error('Error al actualizar aforesConsultadas del usuario:', error)
  }

  res.json(results)
})

// Registra un nuevo usuario, envía correo de verificación y guarda token de verificación
usersRouter.post('/api/register', limiter, async (request, response) => {
    const { name, email, password } = request.body

    try {
        const existingUser = await User.findOne({ email })
        
        if (existingUser) {
            return response.status(400).json({ success: false, message: 'Correo electrónico ya registrado' })
        }
        
        const hashedPassword = await bcrypt.hash(password, 10)

        const currentDate = new Date()
        const expiration = new Date(currentDate.setDate(currentDate.getDate() + 30))
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
usersRouter.post('/api/recovery', limiter, async (request, response) => {
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
usersRouter.get('/api/recovery', limiter, async (request, response) => {
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
usersRouter.post('/api/reset-password', limiter, async (request, response) => {
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
usersRouter.get('/api/verify', limiter, async (request, response) => {
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

module.exports = usersRouter