const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  is2FAEnabled: { type: Boolean, default: false },
  twoFASecret: { type: String },
});

module.exports = mongoose.model('User', UserSchema);
