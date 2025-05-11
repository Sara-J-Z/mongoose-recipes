const mongoose = require('mongoose')

const userSchema = new mongoose.Schema(
  {
    first: { type: String, required: true },
    last: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    picture: { type: String },
    recipes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Recipe' }]
  },
  { timestamps: true }
)

const User = mongoose.model('User', userSchema)

module.exports = User