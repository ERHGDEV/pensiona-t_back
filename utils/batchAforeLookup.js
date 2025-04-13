const axios = require('axios')
const config = require('./config')
const logger = require('./logger')
const { generarEmailAleatorio } = require('../utils/emailUtils')

async function batchAforeLookup({ type, itemsArray }) {
  const results = []
  let successfulQueries = 0

  for (const item of itemsArray) {
    const value = item.toString().toUpperCase().trim()

    const isValid = type === 'nss'
      ? /^\d{11}$/.test(value)
      : /^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$/.test(value)

    if (!isValid) {
      results.push({ [type]: item, afore: 'Formato inválido' })
      continue
    }

    const emailAleatorio = generarEmailAleatorio()
    const url = `${config.URL_MASIVO}/${emailAleatorio}/${type}/${value}`

    try {
      const response = await axios.get(url, {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'Mozilla/5.0',
          Origin: 'https://www.aforeweb.com.mx',
          Referer: 'https://www.aforeweb.com.mx/',
        },
      })

      if (response.data.claveAfore !== null) {
        results.push({ [type]: item, afore: response.data.claveAfore })
        successfulQueries++
      } else if (response.data.diagnostico === 'Recuerda que sólamente puedes realizar una consulta por día.'){
        results.push({ [type]: item, afore: 'Intenta de nuevo mañana' })
      } else if (response.data.diagnostico === 'Lo sentimos, tu consulta generó un error, el NSS o CURP no se encuentra registrado.Si tienes alguna duda sobre el proceso denominado Localiza tu AFORE, llama al 55 1328 5000  (sin costo desde todo el país).”'){
        results.push({ [type]: item, afore: 'No está registrado en una Afore' })
      } else {
        results.push({ [type]: item, afore: 'No se encontró información' })
      }
    } catch (error) {
      logger.error(`Error al consultar AFORE para ${type.toUpperCase()} ${item}:`, error.message)
      results.push({ [type]: item, afore: 'Error en la consulta' })
    }

    await new Promise(resolve => setTimeout(resolve, 100))
  }

  return { results, successfulQueries }
}

module.exports = batchAforeLookup
