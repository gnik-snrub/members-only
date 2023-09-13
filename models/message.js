const mongoose = require('mongoose')

const Schema = mongoose.Schema

const MessageSchema = new Schema({
  title: { type: String, required: true, maxLength: 50 },
  content: { type: String, required: true, maxLength: 200 },
  timestamp: { type: Date, required: true },
  author: { type: Schema.Type.ObjectId, ref: 'User', required: true },
})

