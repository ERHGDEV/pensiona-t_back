require('dotenv').config()

const PORT = process.env.PORT
const MONGODB_URI = process.env.MONGODB_URI
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY
const FROM_EMAIL = process.env.FROM_EMAIL
const JWT_SECRET = process.env.JWT_SECRET
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN
const JWT_REGISTER_EXPIRES_IN = process.env.JWT_REGISTER_EXPIRES_IN
const JWT_RESET_PASSWORD_EXPIRES_IN = process.env.JWT_RESET_PASSWORD_EXPIRES_IN
const URL_FRONTEND = process.env.URL_FRONTEND
const URL_BACKEND = process.env.URL_BACKEND
const MERCADOPAGO_ACCESS_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN
const URL_MASIVO = process.env.URL_MASIVO
const URL_WEBHOOK = process.env.URL_WEBHOOK

module.exports = {
    MONGODB_URI,
    PORT,
    SENDGRID_API_KEY,
    FROM_EMAIL,
    JWT_SECRET,
    JWT_REFRESH_SECRET,
    JWT_EXPIRES_IN,
    JWT_REGISTER_EXPIRES_IN,
    JWT_RESET_PASSWORD_EXPIRES_IN,
    URL_FRONTEND,
    URL_BACKEND,
    MERCADOPAGO_ACCESS_TOKEN,
    URL_MASIVO,
    URL_WEBHOOK
}