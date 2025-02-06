const { generarEmailAleatorio } = require('./emailUtils')
const { incrementUserCounter } = require('./incrementUserCounter')
const User = require('../models/user')
const axios = require('axios')
const config = require('./config')

const consultarAfore = async (tipo, valor, userId) => {
    const emailAleatorio = generarEmailAleatorio()
    const url = `${config.URL_MASIVO}/${emailAleatorio}/${tipo}/${valor}`

    const user = await User.findById(userId)
    if (!user) {
        throw new Error('Usuario no encontrado')
    }

    const hoy = new Date()

    // Definir los límites según el tipo de suscripción
    const limites = {
        free: 1,
        pro: 10,
        unlimited: Infinity
    }

    // Verificar si el usuario ha alcanzado su límite diario
    if (user.aforesConsultadasHoy >= limites[user.subscription]) {
        throw new Error('Has alcanzado el límite de consultas diarias')
    }

    const response = await axios.get(url, {
        headers: {
            Accept: 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            Origin: 'https://www.aforeweb.com.mx',
            Referer: 'https://www.aforeweb.com.mx/',
        }
    })

    if (response.data.claveAfore !== null) {
        await incrementUserCounter(userId, 'aforesConsultadas')
        user.aforesConsultadasHoy += 1
        user.fechaUltimaConsulta = hoy
        await user.save()
    }

    return response
}

module.exports = { consultarAfore }