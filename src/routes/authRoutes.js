const express = require('express');
const {
  login,
  register,
  registerAdmin,
  resetPassword,
} = require('../controllers/authController');

const {
  requireLogin,
  requireAdminPriviledge,
  requireVerification,
} = require('../middlewares/auth/authMiddlewares');

const router = express.Router();

router.route('/login').post(login);

router.route('/register').post(register);

router
  .route('/register-admin')
  .post(
    requireLogin,
    requireVerification,
    requireAdminPriviledge,
    registerAdmin
  );

router.route('/reset-password').post(resetPassword);

module.exports = router;
