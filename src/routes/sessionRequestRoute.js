const express = require('express');

const {
  createSessionRequest,
  getMySessionRequests,
  getPendingSessionRequests,
  acceptSessionRequest,
  rejectSessionRequest,
} = require('../controllers/sessionRequestController');

const {
  requireLogin,
  requireMenteePriviledge,
  requireMentorPriviledge,
  requireVerification,
} = require('../middlewares/auth/authMiddlewares');

const router = express.Router();

router.route('/').get((req, res) => res.send('Hello'));
router
  .route('/create-session-request/:mentorID')
  .post(
    requireLogin,
    requireVerification,
    requireMenteePriviledge,
    createSessionRequest
  );

router
  .route('/my-session-requests')
  .get(
    requireLogin,
    requireVerification,
    requireMenteePriviledge,
    getMySessionRequests
  );

router
  .route('/my-pending-session-requests')
  .get(
    requireLogin,
    requireVerification,
    requireMentorPriviledge,
    getPendingSessionRequests
  );

router
  .route('/accept-session-request/:requestID')
  .put(
    requireLogin,
    requireVerification,
    requireMentorPriviledge,
    acceptSessionRequest
  );

router
  .route('/reject-session-request/:requestID')
  .put(
    requireLogin,
    requireVerification,
    requireMentorPriviledge,
    rejectSessionRequest
  );

module.exports = router;
