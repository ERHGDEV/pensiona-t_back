require('dotenv').config()

const PORT = process.env.PORT
const MONGODB_URI = process.env.MONGODB_URI
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY
const FROM_EMAIL = process.env.FROM_EMAIL
const JWT_SECRET = process.env.JWT_SECRET
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN
const URL_FRONTEND = process.env.URL_FRONTEND

module.exports = {
    MONGODB_URI,
    PORT,
    SENDGRID_API_KEY,
    FROM_EMAIL,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    URL_FRONTEND
}