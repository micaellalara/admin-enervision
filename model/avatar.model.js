const mongoose = require('mongoose');

const avatarSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  imageUrl: {
    type: String,
    required: true,
  },
   createdAt: { type: Date, default: Date.now },
});
const Avatar = mongoose.model('Avatar', avatarSchema);
module.exports = Avatar;