const mongoose = require('mongoose')
const ObjectId = mongoose.Schema.Types.ObjectId

// const notificationSchema = new mongoose.Schema({
//   category: String,
//   sourceId: String,
//   subjectId: String,
//   timestamp: { type: Date, default: Date.now() },
//   text: String,
//   image: String,
//   url: String,
//   seen: { type: Boolean, default: false },
//   clicked: { type: Boolean, default: false }
// })

const userSchema = new mongoose.Schema({
  joined: Date,
  lastOnline: Date,
  lastUpdated: { type: Date, required: true, default: Date.now() },
  verificationToken: { type: String },
  acceptedCodeOfConduct: { type: Boolean, default: false },
  email: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  settings: {
    hemisphere: { type: String, default: 'northern' },
    sendMobileNotifications: { type: Boolean, default: true },
    displayName: String,
    about: String,
    pronouns: String,
    website: String
  },
  expoPushTokens: [String],
})

userSchema.index({ username: 1 })

// create the model for users and expose it to our app
module.exports = mongoose.model('User', userSchema)
