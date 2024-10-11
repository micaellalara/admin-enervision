require('dotenv').config();
const express = require('express');
const connectToDatabase = require('./data/database');
const routes = require('./routes/routes');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();


const PORT = process.env.PORT || 3000;
app.use(express.static(path.join(__dirname, 'public')));

// Parse incoming requests
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.use(cookieParser());
app.set('views', path.join(__dirname, 'views'));

// Use routes
app.use('/', routes);

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
