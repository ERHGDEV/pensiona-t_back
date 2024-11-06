require('dotenv').config()

const PORT = process.env.PORT
const MONGODB_URI = process.env.MONGODB_URI
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY
const FROM_EMAIL = process.env.FROM_EMAIL

module.exports = {
    MONGODB_URI,
    PORT,
    SENDGRID_API_KEY,
    FROM_EMAIL
}