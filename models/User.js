const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      unique: true,
    },
    password: String,
    token: String,
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model('user', UserSchema);

module.exports = User;
