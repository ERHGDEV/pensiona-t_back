const usersRouter = require('express').Router()
const axios = require('axios')
const sgMail = require('@sendgrid/mail')
const User = require('../models/user')
const Payment = require('../models/payment')
const Preference = require('../models/preference')
const Values = require('../models/values')
const config = require('../utils/config')
const logger = require('../utils/logger')
const { generarEmailAleatorio } = require('../utils/emailUtils')
const { consultarAfore } = require('../utils/consultarAfore')
const { incrementUserCounter } = require('../utils/incrementUserCounter')
const { verifyToken } = require('../utils/middleware')
const batchAforeLookup = require('../utils/batchAforeLookup')

sgMail.setApiKey(config.SENDGRID_API_KEY)

// Cierra la sesión del usuario, invalida el token actual
usersRouter.post('/api/logout', verifyToken, async (request, response) => {
    try {
        const user = await User.findById(request.user.id)
        if (user) {
            user.token = null
            user.refreshToken = null
            await user.save()
        }
        response.json({ success: true, message: 'Sesión cerrada' })
    } catch (error) {
        logger.error('Error durante el cierre de sesión: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

// Obtiene el usuario actual y su historial de pagos
usersRouter.get('/api/user', verifyToken, async (request, response) => {
    const hoy = new Date()
    const fechaHoy = new Date(hoy.getFullYear(), hoy.getMonth(), hoy.getDate())
    
    try { 
        const user = await User.findById(request.user.id)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        if (!user.fechaUltimaConsulta || new Date(user.fechaUltimaConsulta) < fechaHoy) {
            user.aforesConsultadasHoy = 0
            user.fechaUltimaConsulta = hoy
            await user.save()
        }

        const preferences = await Preference.find({ email: user.email })
        const externalReferences = preferences.map(pref => pref.external_reference)
        const payments = await Payment.find({ external_reference: { $in: externalReferences } })

        const paymentHistory = payments.map(payment => ({
            date: payment.transactionDate,
            description: payment.amount === 199 ? 'Unlimited' : 'Pro',
            amount: payment.amount,
            status: payment.status
        }))

        const values = await Values.findOne()
        if (!values) {
            return response.status(404).json({ success: false, message: 'No se encontraron valores' })
        }

        response.json({
            name: user.name,
            email: user.email,
            role: user.role,
            expiration: user.expiration,
            subscription: user.subscription || 'free',
            status: user.status,
            created: user.created,
            profileImage: user.profileImage || null,
            calculosRealizados: user.calculosRealizados || 0,
            reportesGenerados: user.reportesGenerados || 0,
            aforesConsultadas: user.aforesConsultadas || 0,
            pdfAnalizados: user.pdfAnalizados || 0,
            aforesConsultadasHoy: user.aforesConsultadasHoy || 0,
            paymentHistory,
            salarioMinimo: values.salarioMinimo, 
            uma: values.uma
        })

    } catch (error) {
        logger.error('Error durante la obtención del usuario: ', error)
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

        const user = await User.findById(request.user.id)
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
        const result = await incrementUserCounter(request.user.id, 'calculosRealizados')
        response.json(result)
    } catch (error) {
        response.status(500).json({ success: false, message: error.message })
    }
})

// Incrementa el contador de reportes generados
usersRouter.put('/api/user/increment-reportes', verifyToken, async (request, response) => {
    try {
        const result = await incrementUserCounter(request.user.id, 'reportesGenerados')
        response.json(result)
    } catch (error) {
        response.status(500).json({ success: false, message: error.message })
    }
})

// Incrementa el contador de PDFs analizados
usersRouter.put('/api/user/increment-pdf', verifyToken, async (request, response) => {
    try {
        const result = await incrementUserCounter(request.user.id, 'pdfAnalizados')
        response.json(result)
    } catch (error) {
        response.status(500).json({ success: false, message: error.message })
    }
})

// Endpoint para hacer la solicitud de consulta de AFORE por NSS
usersRouter.post('/api/afore-info-nss', verifyToken, async (req, res) => {
  const { nss } = req.body

  if (!nss) {
    return res.status(400).json({
      error: 'El campo nss es obligatorio.',
    })
  }

  try {
    const response = await consultarAfore('nss', nss, req.user.id)
    res.status(response.status).json(response.data)
  } catch (error) {
    if (error.message === 'Has alcanzado el límite de consultas diarias') {
        return res.status(429).json({
            error: 'Has alcanzado el límite de consultas diarias',
            message: 'Inténtalo de nuevo mañana'
        })
    }
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
    const response = await consultarAfore('curp', curp, req.user.id)
    res.status(response.status).json(response.data)
  } catch (error) {
    logger.error('Error al hacer la solicitud:', error.message)
    res.status(error.response?.status || 500).json({
      error: 'Error al obtener los datos de AFORE.',
      detalles: error.response?.data || error.message,
    })
  }
})

// Endpoint para hacer la consulta de AFORE por NSS y CURP
usersRouter.post('/api/batch-afore-info', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (user.subscription === 'free' || user.subscription === 'pro') {
    return res.status(403).json({
      error: 'No tienes permiso para realizar esta acción.',
    })
  }

  const { nssArray } = req.body
  if (!Array.isArray(nssArray) || nssArray.length === 0 || nssArray.length > 100) {
    return res.status(400).json({
      error: 'El array de NSS debe contener entre 1 y 100 elementos.',
    })
  }

  const { results, successfulQueries } = await batchAforeLookup({
    type: 'nss',
    itemsArray: nssArray,
    userId: req.user.id,
  })

  try {
    user.aforesConsultadas = (user.aforesConsultadas || 0) + successfulQueries
    await user.save()
    logger.info(`Usuario ${req.user.id} consultó ${successfulQueries} AFOREs exitosamente`)
  } catch (error) {
    logger.error('Error al actualizar aforesConsultadas del usuario:', error)
  }

  res.json(results)
})

usersRouter.post('/api/batch-afore-info-curp', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (user.subscription === 'free' || user.subscription === 'pro') {
    return res.status(403).json({
      error: 'No tienes permiso para realizar esta acción.',
    })
  }

  const { curpArray } = req.body
  if (!Array.isArray(curpArray) || curpArray.length === 0 || curpArray.length > 100) {
    return res.status(400).json({
      error: 'El array de CURP debe contener entre 1 y 100 elementos.',
    })
  }

  const { results, successfulQueries } = await batchAforeLookup({
    type: 'curp',
    itemsArray: curpArray,
    userId: req.user.id,
  })

  try {
    user.aforesConsultadas = (user.aforesConsultadas || 0) + successfulQueries
    await user.save()
    logger.info(`Usuario ${req.user.id} consultó ${successfulQueries} AFOREs por CURP exitosamente`)
  } catch (error) {
    logger.error('Error al actualizar aforesConsultadas del usuario:', error)
  }

  res.json(results)
})  

module.exports = usersRouter