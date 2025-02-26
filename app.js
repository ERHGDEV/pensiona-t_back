const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const config = require('./utils/config')
const logger = require('./utils/logger')
const middleware = require('./utils/middleware')
const usersRouter = require('./controllers/users')
const adminRouter = require('./controllers/admin')
const paymentsRouter = require('./controllers/payments')
const publicRouter = require('./controllers/public')

const app = express()

mongoose.set('strictQuery', false)

logger.info('connecting to DB')

mongoose.connect(config.MONGODB_URI)
    .then(() => {
        logger.info('connected to MongoDB')
    })
    .catch((error) => {
        logger.error('error connecting to MongoDB:', error.message)
    })

app.use(
    cors({
        origin: "https://www.pensiona-t.com", 
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
)

app.use(express.json())
app.use(middleware.requestLogger)

app.set('trust proxy', 1)

app.use('/', publicRouter)
app.use('/', usersRouter)
app.use('/', adminRouter)
app.use('/', paymentsRouter)

app.use(middleware.unknownEndpoint)
app.use(middleware.errorHandler)

module.exports = app