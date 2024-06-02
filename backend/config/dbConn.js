const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.CONNECTION_URL);
    console.log('################ MongoDB connected ################');
  } catch (error) {
    console.log('MongoDB connection failed');
  }
}

module.exports = connectDB;