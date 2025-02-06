const mongoose = require('mongoose')

const preferenceSchema = new mongoose.Schema({
    preference_id: { type: String, required: true, unique: true },
    external_reference: { type: String, required: true },
    email: { type: String, required: true },
    items: { type: Array, required: true },
    total_amount: { type: Number, required: true },
    currency_id: { type: String, required: true },
    statement_descriptor: { type: String },
    status: { type: String, default: 'pending' },
    date_created: { type: Date, default: Date.now },
    expires: { type: Boolean, default: false },
    date_of_expiration: { type: Date, default: null },
    init_point: { type: String, required: true },
    sandbox_init_point: { type: String },
    back_urls: { type: Object },
    notification_url: { type: String }
})

module.exports = mongoose.model('Preference', preferenceSchema)