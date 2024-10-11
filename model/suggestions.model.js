const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const suggestionsSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  postId: { type: Schema.Types.ObjectId, ref: 'Post', required: true }, // Added reference to Post
  suggestionText: { type: String, required: true },
  suggestionDate: { type: Date, default: Date.now },
  deletedAt: { type: Date, default: null }
}, { timestamps: true });

const Suggestion = mongoose.model('Suggestion', suggestionsSchema);

module.exports = Suggestion;



















// Example usage:
/*
// Soft delete a suggestion by updating the deletedAt field
async function softDeleteSuggestion(suggestionId) {
  await Suggestion.findByIdAndUpdate(suggestionId, { deletedAt: new Date() });
}

// Example usage:
softDeleteSuggestion('66dc2bd1b23fc952a559d44f');


// Find all non-deleted suggestions
async function getActiveSuggestions() {
  const suggestions = await Suggestion.find({ deletedAt: null });
  return suggestions;
}

// Example usage:
getActiveSuggestions().then(suggestions => console.log(suggestions));

// Restore a soft-deleted suggestion
async function restoreSuggestion(suggestionId) {
  await Suggestion.findByIdAndUpdate(suggestionId, { deletedAt: null });
}

// Example usage:
restoreSuggestion('66dc2bd1b23fc952a559d44f');
*/