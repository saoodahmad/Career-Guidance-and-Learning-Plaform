const express = require('express');
const { getMySessionsToday } = require('../controllers/sessionsController');

const {
  requireLogin,
  requireVerification,
} = require('../middlewares/auth/authMiddlewares');
const router = express.Router();

router
  .route('/get-my-sessions-by-date/:date')
  .get(requireLogin, requireVerification, getMySessionsToday);

module.exports = router;
