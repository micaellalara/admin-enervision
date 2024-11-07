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
    type: String, 
    required: false 
  },
  bio: {
    type: String,
    required: false 
  }
});

const Admin = mongoose.model('Admin', adminSchema);

module.exports = Admin;