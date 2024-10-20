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
        const user = await User.findById(request.userId)
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

usersRouter.get('/api/admin', verifyToken, verifyAdmin, async (request, response) => {
    try {
        const users = await User.find({ username: { $ne: 'admin' } }).select('-password')
        response.json(users)
    } catch (error) {
        console.error('Error feching users: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.post('/api/admin', verifyToken, verifyAdmin, async (request, response) => {
    const { firstname, lastname, username, password, role } = request.body

    try {
        const existingUser = await User.findOne({ username })
        if (existingUser) {
            return response.json({ success: false, message: 'Correo electrónico ya registrado' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const currentDate = new Date()
        const expiration = new Date(currentDate.setDate(currentDate.getDate() + 15))

        const newUser = new User({
            firstname,
            lastname,
            username,
            password: hashedPassword,
            role,
            expiration
        })

        await newUser.save()

        response.json({ success: true, message: 'Usuario creado exitosamente' })
    } catch (error) {
        console.error('Error during user creation: ', error)
        response.status(500).json({ success: false, message: 'Error en el servidor' })
    }
})

usersRouter.put('/api/admin/users/:id', verifyToken, verifyAdmin, async (request, response) => {
    const { id } = request.params
    const { firstname, lastname, username, role, expiration, status } = request.body

    try {
        const user = await User.findById(id)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        user.firstname = firstname
        user.lastname = lastname
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

usersRouter.post('/api/admin/logout/:userId', verifyToken, verifyAdmin, async (request, response) => {
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

usersRouter.get('/api/user', verifyToken, async (request, response) => {
    try { 
        const user = await User.findById(request.userId)
        if (!user) {
            return response.json({ success: false, message: 'Usuario no encontrado' })
        }

        response.json({
            firstname: user.firstname,
            lastname: user.lastname,
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

function verifyToken(request, response, next) {
    const token = request.headers['authorization']?.split(' ')[1]
  
    if (!token) {
      return response.status(403).json({ success: false, message: 'No token provided' })
    }
  
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        request.userId = decoded.userId
        next()
    } catch (error) {
        console.error('Error during token verification: ', error)
        return response.status(401).json({ success: false, message: 'Unauthorized' })
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