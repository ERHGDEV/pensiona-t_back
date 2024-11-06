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
const checkAndUpdateUserStatus = require('../utils/middleware').checkAndUpdateUserStatus

sgMail.setApiKey(config.SENDGRID_API_KEY)

const generateUniqueToken = (user) => {
    return jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '10m' }
    )
  }
  
const invalidatePreviousToken = async (userId) => {
    await User.findByIdAndUpdate(userId, { token: null })
}

usersRouter.get('/', (request, response) => {
    response.send(`<h1> Pensiona-T </h1>`)
})

usersRouter.post('/api/login', async (request, response) => {
    const { username, password } = request.body
  
    try {
      let user = await User.findOne({ username })
  
      if (!user) {
        await LoginHistory.create({
            username,
            loginDate: new Date(),
            ipAddress: request.ip,
            success: false,
            reason: 'Usuario incorrecto'
        })
        return response.json({ success: false, message: 'Usuario incorrecto' })
      }

      if (!user.verified) {
        await LoginHistory.create({
            userId: user._id,
            username: user.username,
            role: user.role,
            loginDate: new Date(),
            ipAddress: request.ip,
            success: false,
            reason: 'Usuario no verificado'
        })
        return response.json({ success: false, message: 'Cuenta no verificada, revisa tu bandeja de entrada' })
      }
  
      user = await checkAndUpdateUserStatus(user)
  
      if (user.status === 'inactive') {
        await LoginHistory.create({
            userId: user._id,
            username: user.username,
            role: user.role,
            loginDate: new Date(),
            ipAddress: request.ip,
            success: false,
            reason: 'Usuario inactivo'
        })
        return response.json({ success: false, message: 'Usuario inactivo' })
      }
  
      const isMatch = await bcrypt.compare(password, user.password)
  
      if (!isMatch) {
        await LoginHistory.create({
            userId: user._id,
            username: user.username,
            role: user.role,
            loginDate: new Date(),
            ipAddress: request.ip,
            success: false,
            reason: 'Contraseña incorrecta'
        })
        return response.json({ success: false, message: 'Contraseña incorrecta' })
      }
  
      if (user.token) {
        await invalidatePreviousToken(user._id)
      }
  
      const token = generateUniqueToken(user)
  
      user.token = token
      user.isLoggedIn = true
      await user.save()

      if (user.username !== 'admin' && user.username !== 'a@gmail.com' && user.username !== 'erhgdev@gmail.com') {
        await LoginHistory.create({
            userId: user._id,
            username: user.username,
            role: user.role,
            loginDate: new Date(),
            ipAddress: request.ip,
            success: true,
            reason: 'Inicio de sesión exitoso'
        })
      }
  
      response.json({ success: true, username: user.username, role: user.role, token })
    } catch (error) {
      console.error('Error durante el inicio de sesión: ', error)
      response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})
  
usersRouter.post('/api/logout', verifyToken, async (request, response) => {
    const user = await User.findById(request.userId)

    try {
      
      user.isLoggedIn = false
      await user.save()

      await invalidatePreviousToken(request.userId)
      response.json({ success: true, message: 'Sesión cerrada' })
    } catch (error) {
      console.error('Error durante el cierre de sesión: ', error)
      response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/admin', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const users = await User.find({ username: { $ne: 'admin' } }).select('-password')
        response.json(users)
    } catch (error) {
        console.error('Error feching users: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/admin/users', verifyToken, verifyAdmin, async (request, response) => {
    const { numeroConsar, firstname, username, password, secretQuestion, secretAnswer, role } = request.body

    try {
        const existingUser = await User.findOne({ username })
        if (existingUser) {
            return response.json({ success: false, message: 'Correo electrónico ya registrado' })
        }
        const existingConsar = await User.findOne({ numeroConsar })
        if (existingConsar) {
            return response.json({ success: false, message: 'Número CONSAR ya registrado' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const currentDate = new Date()
        const expiration = new Date(currentDate.setDate(currentDate.getDate() + 30))
        const verificationToken = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1d' })

        const newUser = new User({
            numeroConsar,
            firstname,
            username,
            password: hashedPassword,
            secretQuestion,
            secretAnswer,
            role,
            expiration,
            verificationToken
        })

        await newUser.save()
        //actualizar a config.URL_FRONTEND
        const verificationUrl = `http://localhost:5173/verify?token=${verificationToken}`

        const verificationEmail = createVerificationEmail(firstname, username, verificationUrl)

        try {
            await sgMail.send(verificationEmail)
        } catch (error) {
            console.error('Error sending verification email: ', error)
            return response.json({ success: false, message: 'Error al enviar el correo de verificación' })
        }

        response.json({ success: true, message: 'Usuario creado exitosamente' })
    } catch (error) {
        console.error('Error during user creation: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.put('/api/admin/users/:id', verifyToken, verifyAdmin, async (request, response) => {
    const { id } = request.params
    const { numeroConsar, firstname, username, role, expiration, status } = request.body

    try {
        const user = await User.findById(id)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        user.numeroConsar = numeroConsar
        user.firstname = firstname
        user.username = username
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

usersRouter.post('/api/admin/users/logout/:userId', verifyToken, verifyAdmin, async (request, response) => {
    const { userId } = request.params

    try {
        const user = await User.findById(userId)
        if (!user) {
            return response.status(404).json({ success: false, message: 'Usuario no encontrado' })
        }

        user.isLoggedIn = false
        await user.save()

        response.json({ success: true, message: 'Sesión del usuario cerrada exitosamente' })
    } catch (error) {
        console.error('Error during user logout: ', error)
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
            numeroConsar: user.numeroConsar,
            firstname: user.firstname,
            username: user.username,
            role: user.role,
            expiration: user.expiration,
            status: user.status,
            isLoggedIn: user.isLoggedIn
        })
    } catch (error) {
        console.error('Error during user check: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/verify-consar', async (req, res) => {
    const { numeroConsar } = req.body

    const url = 'http://www.apromotores.com.mx/siap-agentepromotor/redirectResultadoConsulta.do'
    const data = new URLSearchParams({
        numeroAgentePromotor: numeroConsar,
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
})

usersRouter.post('/api/register', async (request, response) => {
    const { numeroConsar, firstname, username, password, secretQuestion, secretAnswer } = request.body

    try {
        const existingUser = await User.findOne({ username })
        if (existingUser) {
            return response.status(400).json({ success: false, message: 'Correo electrónico ya registrado' })
        }
        const existingConsar = await User.findOne({ numeroConsar })
        if (existingConsar) {
            return response.status(400).json({ success: false, message: 'Número CONSAR ya registrado' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const currentDate = new Date()
        const expiration = new Date(currentDate.setDate(currentDate.getDate() + 30))

        const newUser = new User({
            numeroConsar,
            firstname,
            username,
            password: hashedPassword,
            secretQuestion,
            secretAnswer,
            expiration
        })

        await newUser.save()

        response.json({ success: true, message: 'Usuario registrado' })
    } catch (error) {
        console.error('Error during registration: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/recovery/step1', async (request, response) => {
    const { email } = request.body

    try {
        const user = await User.findOne({ username: email })
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        response.json({ success: true, secretQuestion: user.secretQuestion })
    } catch (error) {
        console.error('Error during recovery step 1:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/recovery/step2', async (request, response) => {
    const { email, secretAnswer } = request.body

    try {
        const user = await User.findOne({ username: email })
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        if (user.secretAnswer !== secretAnswer) {
            return response.json({ success: false, message: 'Respuesta incorrecta' })
        }

        response.json({ success: true, message: 'Respuesta correcta' })
    } catch (error) {
        console.error('Error during recovery step 2:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/recovery/step3', async (request, response) => {
    const { email, newPassword } = request.body

    try {
        const user = await User.findOne({ username: email })
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        user.password = hashedPassword
        await user.save()

        response.json({ success: true, message: 'Contraseña actualizada exitosamente' })
    } catch (error) {
        console.error('Error during recovery step 3:', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/verify', async (request, response) => {
    const { token } = request.query

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        const user = await User.findOne({ username: decoded.username })

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
            if (decoded && decoded.username) {
                const user = await User.findOne({ username: decoded.username })

                if (user && !user.verified) {
                    await User.deleteOne({ username: decoded.username })
                    return response.status(410).json({ success: false, message: 'Token expirado. Debe registrarse nuevamente' })
                }
            }
        }

        console.error('Error during verification:', error)
        return response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})


async function verifyToken(request, response, next) {
    const token = request.headers['authorization']?.split(' ')[1]
  
    if (!token) {
      return response.status(403).json({ success: false, message: 'No se proporcionó token' })
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET)
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

module.exports = usersRouter