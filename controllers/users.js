const usersRouter = require('express').Router()
const User = require('../models/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const checkAndUpdateUserStatus = require('../utils/middleware').checkAndUpdateUserStatus

usersRouter.get('/', (request, response) => {
    response.send(`<h1> Pensiona-T </h1>`)
})

usersRouter.post('/api/login', async (request, response) => {
    const { username, password } = request.body

    try {
        let user = await User.findOne({ username })

        if (!user) {
            return response.json({ success: false, message: 'Usuario incorrecto' })
        }

        user = await checkAndUpdateUserStatus(user)

        if (user.status === 'inactive') {
            return response.json({ success: false, message: 'Usuario inactivo' })
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch) {
            return response.json({ success: false, message: 'Contraseña incorrecta' })
        }

        if (user.isLoggedIn) {
            return response.json({ success: false, message: 'Ya existe una sesión activa' })
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '30m' }
        )

        user.isLoggedIn = true
        await user.save()

        response.json({ success: true, role: user.role, token })
    } catch (error) {
        console.error('Error during login: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/logout', verifyToken, async (request, response) => {
    try { 
        const user = await User.findById(request.user.userId)
        if (user) {
            user.isLoggedIn = false
            await user.save()
        }

        response.json({ success: true, message: 'Sesión cerrada' })
    } catch (error) {
        console.error('Error during logout: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/admin', verifyToken, async (request, response) => {
    try {
        const user = await User.findById(request.user.userId)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        await checkAndUpdateUserStatus(user)

        if (user.status === 'inactive') {
            return response.json({ success: false, message: 'Usuario inactivo' })
        }

        if (user.role === 'admin') {
            return response.json({ success: true })
        } else {
            return response.json({ success: false, message: 'No autorizado' })
        }
    } catch (error) {
        console.error('Error during admin check: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.get('/api/user', verifyToken, async (request, response) => {
    try { 
        const user = await User.findById(request.user.userId)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        await checkAndUpdateUserStatus(user)

        if (user.status === 'inactive') {
            return response.json({ success: false, message: 'Usuario inactivo' })
        }

        if (user.role === 'user') {
            return response.json({ success: true })
        } else {
            return response.json({ success: false, message: 'No autorizado' })
        }
    } catch (error) {
        console.error('Error during user check: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

function verifyToken(request, response, next) {
    const token = request.headers['authorization']?.split(' ')[1]
  
    if (!token) {
      return response.status(403).json({ success: false, message: 'No token provided' })
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return response.status(401).json({ success: false, message: 'Failed to authenticate token' })
      }
      request.user = decoded
      next()
    })
}

/* usersRouter.post('/api/temporal-register', async (request, response) => {
    const { firstname, lastname, username, password } = request.body

    try {
        const existingUser = await User.findOne({ username })
        if (existingUser) {
            return response.status(400).json({ success: false, message: 'Correo electrónico ya registrado' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const currentDate = new Date()
        const expiration = new Date(currentDate.setDate(currentDate.getDate() + 7))

        const newUser = new User({
            firstname,
            lastname,
            username,
            password: hashedPassword,
            expiration
        })

        await newUser.save()

        response.json({ success: true, message: 'Usuario registrado' })
    } catch (error) {
        console.error('Error during registration: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
}) */

module.exports = usersRouter