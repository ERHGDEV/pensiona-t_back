const { generarEmailAleatorio } = require('./emailUtils')
const { incrementUserCounter } = require('./incrementUserCounter')
const axios = require('axios')
const User = require('../models/user')

const consultarAfore = async (tipo, valor, userId) => {
    const emailAleatorio = generarEmailAleatorio()
    const url = `https://api.esar.io/sartoken/externos/web/localizatuafore/afore/${emailAleatorio}/${tipo}/${valor}`

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
    }

    return response
}

module.exports = { consultarAfore }