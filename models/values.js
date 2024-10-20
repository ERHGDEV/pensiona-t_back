const mongoose = require('mongoose')

const valuesSchema = new mongoose.Schema({
    salarioMinimo: { type: Number, required: true },
    uma: { type: Number, required: true }
})

module.exports = mongoose.model('Values', valuesSchema)