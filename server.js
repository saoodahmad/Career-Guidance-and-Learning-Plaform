require('dotenv').config();

const express = require('express');
const cors = require('cors');

const authRoutes = require('./src/routes/authRoutes');

const userRoutes = require('./src/routes/userRoutes');

const verificationRequestRoutes = require('./src/routes/verificationRequestRoutes');

const sessionRequestRoute = require('./src/routes/sessionRequestRoute');

const sessionRoute = require('./src/routes/sessionRoutes');
const connectDB = require('./src/utils/db.utils.js');

const errorHandler = require('./src/error-handler/errorHandler');

const app = express();

connectDB();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  cors({
    origin: '*',
    credentials: true,
  })
);
app.use(express.static('public'));
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/profile-verification', verificationRequestRoutes);
app.use('/api/session-request', sessionRequestRoute);
app.use('/api/session', sessionRoute);

app.use(errorHandler);

const server = app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

process.on('unhandledRejection', (err, promise) => {
  console.error(`Logged Error: ${err}`);
  server.close(() => process.exit(1));
});
