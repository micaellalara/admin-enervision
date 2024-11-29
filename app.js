require('dotenv').config();
const express = require('express');
const { connectToDatabase } = require('./data/database');
const routes = require('./routes/routes');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http'); 
const { Server } = require('socket.io'); 

const app = express();
const PORT = process.env.PORT || 3000;

const server = http.createServer(app);
const io = new Server(server);
const methodOverride = require('method-override');
app.use(methodOverride('_method'));



app.use(express.static(path.join(__dirname, 'public')));
    

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.use(cookieParser());
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));


connectToDatabase(io); 

app.use('/', routes);

io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });

   
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
