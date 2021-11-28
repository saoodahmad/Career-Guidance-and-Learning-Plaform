const express = require('express');
const {
  getVerificationDocumentURL,
  createVerificationRequest,
  getMyVerificationRequests,
  getPendingVerificationRequests,
  approveVerificationRequest,
  rejecteVerificationRequest,
} = require('../controllers/verificationController');

const {
  requireLogin,
  requireAdminPriviledge,
  requireVerification,
} = require('../middlewares/auth/authMiddlewares');
const { uploadVerificationDocument } = require('../multer/fileUpload');

const router = express.Router();

router
  .route('/my-verification-requests')
  .get(requireLogin, getMyVerificationRequests);

router
  .route('/create-verification-request')
  .post(requireLogin, createVerificationRequest);

router.route('/upload-verification-document').post(
  requireLogin,
  function (req, res, next) {
    uploadVerificationDocument(req, res, function (err) {
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
  getVerificationDocumentURL
);

router
  .route('/admin/pending-verification-requests')
  .get(
    requireLogin,
    requireVerification,
    requireAdminPriviledge,
    getPendingVerificationRequests
  );

router
  .route('/admin/approve-user-verification-request')
  .put(
    requireLogin,
    requireVerification,
    requireAdminPriviledge,
    approveVerificationRequest
  );

router
  .route('/admin/reject-user-verification-request')
  .put(
    requireLogin,
    requireVerification,
    requireAdminPriviledge,
    rejecteVerificationRequest
  );
module.exports = router;
