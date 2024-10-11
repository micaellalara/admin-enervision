const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const postSchema = new Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  uploadPhoto: String,
  deletedAt: Date,
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  suggestions: [{ type: Schema.Types.ObjectId, ref: 'Suggestion' }],
  flagged: { // New field to indicate if a post is flagged
    type: Boolean,
    default: false // Default to false
  }
}, { timestamps: true });

postSchema.index({ userId: 1 });

module.exports = mongoose.model('Post', postSchema);
