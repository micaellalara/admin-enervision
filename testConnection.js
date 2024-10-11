const mongoose = require('mongoose');
const User = require('./model/users');

const uri = process.env.MONGODB_URI || 'mongodb+srv://22104647:J%40mes2004@enervision-main.elxae.mongodb.net/enervision?retryWrites=true&w=majority';

async function testConnection() {
    try {
        await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log('Connected to MongoDB');

        const users = await User.find(); // Fetch all users
        console.log('Fetched Users:', users);
        mongoose.connection.close();
    } catch (error) {
        console.error('Error:', error);
    }
}

testConnection();
