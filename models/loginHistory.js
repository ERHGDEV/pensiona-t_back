const mongoose = require('mongoose')

const loginHistorySchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
  },
  loginDate: {
    type: Date,
    default: Date.now,
  },
  ipAddress: {
    type: String,
  }
})

module.exports = mongoose.model('LoginHistory', loginHistorySchema)