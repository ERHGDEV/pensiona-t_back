const mongoose = require('mongoose')

const WebhookSchema = new mongoose.Schema({
    action: String,
    api_version: String,
    data: {
        id: String
    },
    date_created: Date,
    notification_id: Number,
    live_mode: Boolean,
    type: String,
    user_id: String
}, { timestamps: true })

module.exports = mongoose.model('WebhookNotification', WebhookSchema)