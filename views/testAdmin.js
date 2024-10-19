const mongoose = require('mongoose');
const { Admin } = require('./model/admins'); 

const uri = 'your_mongodb_connection_string';

async function testAdminModel() {
    try {
        await mongoose.connect(uri);
        console.log('Connected to MongoDB');

        // Test the Admin model
        const admin = await Admin.findOne({}); // Try to fetch an admin or create a new one for testing
        if (admin) {
            console.log('Admin found:', admin);
        } else {
            console.log('No admin found, creating one for testing...');
            const newAdmin = new Admin({ name: 'Test Admin', email: 'test@admin.com', password: 'password123' });
            await newAdmin.save();
            console.log('New admin created:', newAdmin);
        }
    } catch (error) {
        console.error('Error fetching admin:', error.message);
    } finally {
        mongoose.connection.close();
    }
}

testAdminModel();
