require('dotenv').config();

const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.DB_URI);
    console.log('MONGODB connection SUCCESS');
  } catch (error) {
    console.error(`MongoDB connection FAIL ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
