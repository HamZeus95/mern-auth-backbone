const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');
const corsOptions = require('./config/corsOptions')
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
require('dotenv').config();
require('express-async-errors');
const PORT = process.env.PORT || 5000;
const connectDB = require('./config/dbConn');
const errorHandler = require('./middleware/errorHandler'); 
const { logger, logEvents } = require('./middleware/logger');

// Connect to MongoDB
connectDB();

app.use(logger);

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(errorHandler);
mongoose.connection.once('open', () => {
    console.log('Connected to MongoDB')
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
});

mongoose.connection.on('error', err => {
    console.log(err)
    logEvents(`${err.no}: ${err.code}\t${err.syscall}\t${err.hostname}`, 'mongoErrLog.log')
});

// Routes
const userRoutes = require('./routes/UserRoute');


// endpoints
app.use('/api/users', userRoutes); 

