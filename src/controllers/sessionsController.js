const ErrorResponse = require('../error-handler/errorResponse');

const { getMySessionsInADateRange } = require('../services/sessionsService');
exports.getMySessionsToday = async (req, res, next) => {
  try {
    const date = req.params.date;

    const start = new Date(date);

    const end = new Date(date).getTime() + 24 * 60 * 60 * 1000;

    const { _id: userID, role } = req.user;

    const sessions = await getMySessionsInADateRange(userID, role, start, end);

    if (sessions.length === 0) {
      return next(new ErrorResponse('No sessions today', 404));
    }

    return res.status(200).json({
      success: true,
      sessions,
    });
  } catch (error) {
    return next(error);
  }
};
