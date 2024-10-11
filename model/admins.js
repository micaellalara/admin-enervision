const mongoose = require('mongoose');


const adminSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  picture: {
    type: String, // Assuming picture will be stored as a URL
    required: false // Not required, adjust as needed
  },
  bio: {
    type: String,
    required: false // Not required, adjust as needed
  }
});

// Create a model based on the schema
const Admin = mongoose.model('Admin', adminSchema);

module.exports = Admin;