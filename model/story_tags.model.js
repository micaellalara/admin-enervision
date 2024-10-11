const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const storyTagsSchema = new Schema({
  storyTitle: {
    type: String,
    required: true
  },
  storyText: {
    type: String,
    required: true
  },
  uploadPhoto: String,
});

const StoryTags = mongoose.model('StoryTag', storyTagsSchema);

module.exports = StoryTags;






