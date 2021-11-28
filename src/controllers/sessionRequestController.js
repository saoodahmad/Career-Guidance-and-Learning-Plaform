const ErrorResponse = require('../error-handler/errorResponse');
const {
  createSessionRequest,
  getSessionRequestsByMentorID,
  getSessionRequestsByMenteeID,
  getSessionRequestsByID,
  updateSessionRequestsByID,
} = require('../services/sessionRequestsService');
const {
  getSessionInATimeRange,
  getSessionsInATimeRange,
  createSession,
} = require('../services/sessionsService');
const {
  getMentorById,
  getMentorByIdService,
} = require('../services/usersService');

exports.createSessionRequest = async (req, res, next) => {
  try {
    const { _id: menteeID, name: menteeName } = req.user;
    const { mentorID } = req.params;

    const { start, duration, subject, end } = req.body;

    if (!start || !subject || !end || !duration || duration <= 0) {
      return next(new ErrorResponse('Invalid Request'));
    }

    const { category, name: mentorName } = await getMentorByIdService(mentorID);

    console.log(category, mentorName);
    if (!category || !mentorName) {
      return next(new ErrorResponse('Cannot Process Request', 400));
    }
    const sessionRequest = await createSessionRequest({
      menteeID,
      mentorID,
      menteeName,
      mentorName,
      start: new Date(start),
      duration,
      status: 'Pending',
      subject: subject || 'Excited to be your mentee',
      category,
      end: new Date(end),
    });

    return res.status(201).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};

exports.getMySessionRequests = async (req, res, next) => {
  try {
    const menteeID = req.user._id;

    const sessionRequests = await getSessionRequestsByMenteeID(menteeID);

    if (!sessionRequests.length === 0) {
      return next(new ErrorResponse('No Session Request Found', 404));
    }

    return res.status(200).json({
      success: true,
      sessionRequests,
    });
  } catch (error) {
    next(error);
  }
};

exports.getPendingSessionRequests = async (req, res, next) => {
  try {
    const mentorID = req.user._id;

    const sessionRequests = await getSessionRequestsByMentorID(mentorID);

    if (sessionRequests.length === 0) {
      return next(new ErrorResponse('No Pending Session Request Found', 404));
    }

    return res.status(200).json({
      success: true,
      sessionRequests,
    });
  } catch (error) {
    next(error);
  }
};

exports.acceptSessionRequest = async (req, res, next) => {
  try {
    const requestID = req.params.requestID;

    const request = await getSessionRequestsByID(requestID);

    const { remark, sessionLink } = req.body;

    if (!sessionLink) {
      return next(new ErrorResponse('Please Provide Session Link', 400));
    }

    const {
      menteeID,
      mentorID,
      duration,
      start,
      end,
      category,
      mentorName,
      menteeName,
    } = request;

    const sessions = await getSessionsInATimeRange({
      menteeID,
      mentorID,
      duration,
      start,
      end,
      category,
    });

    if (sessions.length !== 0) {
      return next(new ErrorResponse('You are Not free'));
    }

    const newSession = await createSession({
      sessionRequestID: requestID,
      mentorID,
      menteeID,
      duration,
      start,
      end,
      category,
      mentorName,
      menteeName,
      sessionLink,
    });

    const updatedSessionRequest = await updateSessionRequestsByID(requestID, {
      sessionID: newSession._id,
      status: 'Accepted',
      remark: remark,
    });

    return res.status(201).json({
      success: true,
    });
  } catch (error) {
    next(error);
  }
};

exports.rejectSessionRequest = async (req, res, next) => {
  try {
    const requestID = req.params.requestID;

    const request = await getSessionRequestsByID(requestID);

    const { remark } = req.body;

    const updatedSessionRequest = await updateSessionRequestsByID(requestID, {
      status: 'Rejected',
      remark: remark,
    });

    return res.status(201).json({
      success: true,
    });
  } catch (error) {
    next(error);
  }
};
