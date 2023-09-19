const { DateTime } = require('luxon')

const mongoose = require('mongoose')

const Schema = mongoose.Schema

const MessageSchema = new Schema({
  content: { type: String, required: true, maxLength: 200 },
  timestamp: { type: Date, required: true },
  author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
})

MessageSchema.virtual('formatted_timestamp').get(function() {
  return DateTime.fromJSDate(this.timestamp).toLocaleString(DateTime.DATETIME_SHORT)
})

module.exports = mongoose.model('Message', MessageSchema)
