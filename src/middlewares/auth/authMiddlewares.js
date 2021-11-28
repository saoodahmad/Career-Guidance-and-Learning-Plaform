const ErrorResponse = require('../../error-handler/errorResponse');
const { getUserFromTokenService } = require('../../services/usersService');

exports.requireLogin = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1];

      const user = await getUserFromTokenService(token);

      if (!user) {
        return next(new ErrorResponse('User not found', 401));
      }

      req.user = user;
      return next();
    } catch (error) {
      console.log(error.message);
      return next(new ErrorResponse('Not Authorised', 401));
    }
  } else {
    return next(new ErrorResponse('Not Authorised', 401));
  }
};

exports.requireAdminPriviledge = async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return next(new ErrorResponse('Forbidden', 403));
  }

  return next();
};

exports.requireMenteePriviledge = async (req, res, next) => {
  if (req.user.role !== 'mentee') {
    return next(new ErrorResponse('Forbidden', 403));
  }

  return next();
};

exports.requireMentorPriviledge = async (req, res, next) => {
  if (req.user.role !== 'mentor') {
    return next(new ErrorResponse('Forbidden', 403));
  }

  return next();
};

exports.requireVerification = (req, res, next) => {
  if (req.user.isVerified !== true) {
    return next(new ErrorResponse('Please complete profile verification', 401));
  }

  return next();
};
