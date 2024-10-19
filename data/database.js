const mongoose = require('mongoose');
const Admin = require('../model/admins');
const User = require('../model/users');

// Use the URI from the .env file
const uri = process.env.MONGODB_URI || 'mongodb+srv://22104647:J%40mes2004@enervision-main.elxae.mongodb.net/enervision?retryWrites=true&w=majority';

async function connectToDatabase() {
  try {
    // Connect directly to the enervision database
    await mongoose.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected successfully to MongoDB');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error.message);
  }
}

async function addAdmin(name, email, password) {
  try {
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      throw new Error('Admin with this email already exists.');
    }

    const newAdmin = new Admin({
      name,
      email,
      password,
    });

    await newAdmin.save();
    console.log('Admin saved successfully');
  } catch (err) {
    console.error('Error saving admin:', err.message);
    throw err;
  }
}

module.exports = {
  connectToDatabase,
  addAdmin,
  Admin,
  User,
};

// Connect to the database when the module is loaded
connectToDatabase();