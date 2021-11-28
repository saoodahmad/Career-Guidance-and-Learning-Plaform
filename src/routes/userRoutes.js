const express = require('express');

const {
  getDashboard,
  getMyProfile,
  getProfileImageURL,
  updateMyProfile,
  getUserProfile,
  getMentorById,
  getMentors,
  getMentorsByCategory,
} = require('../controllers/usersController');
const {
  requireLogin,
  requireAdminPriviledge,
  requireVerification,
} = require('../middlewares/auth/authMiddlewares');

const { uploadProfileImage } = require('../multer/fileUpload');
const router = express.Router();

router.route('/my-dashboard').get(requireLogin, getDashboard);

router.route('/my-profile').get(requireLogin, getMyProfile);

router.route('/update-my-profile').put(requireLogin, updateMyProfile);

router.route('/upload-profile-image').post(
  requireLogin,
  function (req, res, next) {
    uploadProfileImage(req, res, function (err) {
      if (err) {
        /* if error is multer error and error code is "LIMIT_UNEXPECTED_FILE" */
        if (
          err.name === 'MulterError' &&
          err.code === 'LIMIT_UNEXPECTED_FILE'
        ) {
          return next(new ErrorResponse('Invalid upload request', 400));
        }
        return next(new ErrorResponse(err.message, 400));
      }

      next();
    });
  },
  getProfileImageURL
);

router
  .route('/get-user-profile/:id')
  .get(
    requireLogin,
    requireVerification,
    requireAdminPriviledge,
    getUserProfile
  );

router.route('/get-mentor-by-id/:mentorID').get(getMentorById);

router.route('/get-mentors-by-category/:category').get(getMentorsByCategory);

router.route('/get-mentors').get(getMentors);

module.exports = router;
