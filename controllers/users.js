const usersRouter = require('express').Router()
const fetch = require('node-fetch')
const cheerio = require('cheerio')
const User = require('../models/user')
const Values = require('../models/values')
const LoginHistory = require('../models/loginHistory')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('../utils/config')
const sgMail = require('@sendgrid/mail')
const createVerificationEmail = require('../utils/emailTemplates').createVerificationEmail
const createRecoveryEmail = require('../utils/emailTemplates').createRecoveryEmail
const checkAndUpdateUserStatus = require('../utils/middleware').checkAndUpdateUserStatus

sgMail.setApiKey(config.SENDGRID_API_KEY)

async function verifyToken(request, response, next) {
    const token = request.headers['authorization']?.split(' ')[1]
  
    if (!token) {
      return response.status(403).json({ success: false, message: 'No se proporcionó token' })
    }
  
    try {
      const decoded = jwt.verify(token, config.JWT_SECRET)
      const user = await User.findById(decoded.userId)
  
      if (!user || user.token !== token) {
        return response.status(401).json({ success: false, message: 'Token inválido. Por favor, inicie sesión nuevamente.' })
      }
  
      request.userId = decoded.userId
      next()
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return response.status(401).json({ success: false, message: 'El token ha expirado. Por favor, inicie sesión nuevamente.' })
      } else {
        console.error('Error durante la verificación del token: ', error)
        return response.status(401).json({ success: false, message: 'No autorizado' })
      }
    }
  }
  

async function verifyAdmin(request, response, next) {
    try {
        const user = await User.findById(request.userId)
        if (user.role !== 'admin') {
            return response.status(403).json({ message: 'No autorizado' })
        }
        next()
    } catch (error) {
        console.error('Error during admin verification: ', error)
        response.status(500).json({ message: 'Error en el servidor' })
    }
}

const generateUniqueToken = (user) => {
    return jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    )
}
  
const invalidatePreviousToken = async (userId) => {
    await User.findByIdAndUpdate(userId, { token: null })
}

usersRouter.get('/', (request, response) => {
    response.redirect('https://pensiona-t.vercel.app/')
})

usersRouter.post('/api/login', async (request, response) => {
    const { email, password } = request.body
  
    try {
      let user = await User.findOne({ email })
  
      if (!user) {
        return response.json({ success: false, message: 'Usuario incorrecto' })
      }

      if (!user.verified) {
        return response.json({ success: false, message: 'Cuenta no verificada, revisa tu bandeja de entrada' })
      }
  
      user = await checkAndUpdateUserStatus(user)
  
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

      if (user.email !== 'admin' && user.email !== 'a@gmail.com' && user.email !== 'erhgdev@gmail.com') {
        await LoginHistory.create({
            email: user.email,
            role: user.role,
            ipAddress: request.ip
        })
      }
  
      response.json({ success: true, email: user.email, role: user.role, token })
    } catch (error) {
      console.error('Error durante el inicio de sesión: ', error)
      response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})
  
usersRouter.post('/api/logout', verifyToken, async (request, response) => {
    try {
      await invalidatePreviousToken(request.userId)
      response.json({ success: true, message: 'Sesión cerrada' })
    } catch (error) {
      console.error('Error durante el cierre de sesión: ', error)
      response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/admin', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const users = await User.find({ email: { $ne: 'admin' } }).select('-password')
        response.json(users)
    } catch (error) {
        console.error('Error feching users: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

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
        //actualizar a config.URL_FRONTEND
        const verificationUrl = `http://localhost:5173/verify?token=${verificationToken}`
        const verificationEmail = createVerificationEmail(name, email, verificationUrl)
        await sgMail.send(verificationEmail)

        response.json({ success: true, message: 'Usuario creado exitosamente' })
    } catch (error) {
        console.error('Error during user creation: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

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
        console.error('Error during user update: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

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
        console.error('Error during user deletion: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/admin/values', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const values = await Values.findOne()
        if (!values) {
            return response.json({ success: false, message: 'No se encontraron valores' })
        }
        response.json({ success: true, salarioMinimo: values.salarioMinimo, uma: values.uma })
    } catch (error) {
        console.error('Error fetching values: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

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
        console.error('Error updating values: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/values', async (request, response) => {
    try {
        const values = await Values.findOne()
        if (!values) {
            return response.status(404).json({ success: false, message: 'No se encontraron valores' })
        }
        response.json({ success: true, salarioMinimo: values.salarioMinimo, uma: values.uma })
    } catch (error) {
        console.error('Error fetching values: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

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
            status: user.status
        })
    } catch (error) {
        console.error('Error during user check: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

/* usersRouter.post('/api/verify-consar', async (req, res) => {
    const { numeroAgentePromotor } = req.body

    const url = 'http://www.apromotores.com.mx/siap-agentepromotor/redirectResultadoConsulta.do'
    const data = new URLSearchParams({
        numeroAgentePromotor: numeroAgentePromotor,
        apellidoPaterno: '',
        apellidoMaterno: '',
        nombre: '',
        mensajeError: '',
        mensajeSinResultados: '',
        fechaUltimaActualizacion: '',
    })

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: data
        })
        
        const html = await response.text()
        const $ = cheerio.load(html)

        let resultado = { estatus: '', nombre: '' }

        $('td').each((index, element) => {
            const text = $(element).text().trim()
            if (text.includes('Nombre:')) resultado.nombre = text.split('Nombre:')[1].trim()
            if (text.includes('Estatus:')) resultado.estatus = text.split('Estatus:')[1].trim()
        })

        if (!resultado.nombre || !resultado.estatus) {
            return res.status(400).json({ success: false, message: 'No se encontraron resultados para el número CONSAR' })
        }

        res.json({ success: true, nombre: resultado.nombre, estatus: resultado.estatus })
    } catch (error) {
        console.error('Error al verificar el número CONSAR:', error)
        res.status(500).json({ success: false, message: 'Error en el servidor al verificar el número CONSAR' })
    }
}) */

usersRouter.post('/api/register', async (request, response) => {
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
        //actualizar a config.URL_FRONTEND
        const verificationUrl = `http://localhost:5173/verify?token=${verificationToken}`
        const verificationEmail = createVerificationEmail(name, email, verificationUrl)
        await sgMail.send(verificationEmail)

        response.json({ success: true, message: 'Usuario registrado, revisa tu bandeja de entrada' })
    } catch (error) {
        console.error('Error during registration: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/recovery', async (request, response) => {
    const { email } = request.body

    try {
        const user = await User.findOne({ email: email })
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        const recoveryToken = jwt.sign({ email }, config.JWT_SECRET, { expiresIn: '1d' })
        user.recoveryToken = recoveryToken
        await user.save()

        //actualizar a config.URL_FRONTEND
        const recoveryUrl = `http://localhost:5173/recovery?token=${recoveryToken}`
        /* const recoveryEmail = createRecoveryEmail(user.name, email, recoveryUrl)
        await sgMail.send(recoveryEmail) */
        console.log(recoveryUrl)

        response.json({ success: true, message: 'Correo de recuperación enviado, revisa tu bandeja de entrada' })
    } catch (error) {
        console.error('Error during recovery:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/recovery', async (request, response) => {
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

        console.error('Error during validation:', error)
        return response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})


usersRouter.post('/api/reset-password', async (request, response) => {
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
        console.error('Error during password reset:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/verify', async (request, response) => {
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

        console.error('Error during verification:', error)
        return response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

module.exports = usersRouter