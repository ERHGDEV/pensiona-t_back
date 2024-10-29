const mongoose = require('mongoose')

const loginHistorySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  username: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: null,
  },
  loginDate: {
    type: Date,
    default: Date.now,
  },
  ipAddress: {
    type: String,
  },
  success: {
    type: Boolean,
    required: true,
  },
})

module.exports = mongoose.model('LoginHistory', loginHistorySchema)