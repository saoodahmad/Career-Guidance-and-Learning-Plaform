const SessionRequest = require('../models/sessionRequestModel');
const { getUserByIdService } = require('./usersService');

exports.createSessionRequest = async (fields) => {
  return await SessionRequest.create({ ...fields });
};

exports.getMentorCategory = async (mentorID) => {
  const user = await getUserByIdService(mentorID);

  return user.category;
};

exports.getSessionRequestsByMenteeID = async (menteeID) => {
  return await SessionRequest.find({ menteeID });
};

exports.getSessionRequestsByID = async (ID) => {
  return await SessionRequest.findById(ID);
};

exports.getSessionRequestsByMentorID = async (mentorID) => {
  return await SessionRequest.find({ mentorID, status: 'Pending' });
};

exports.updateSessionRequestsByID = async (
  ID,
  { sessionID, status, remark }
) => {
  if (status === 'Accepted') {
    return await SessionRequest.findByIdAndUpdate(ID, {
      sessionID,
      status,
      remark: remark || status,
    });
  }

  return await SessionRequest.findByIdAndUpdate(ID, {
    status,
    remark: remark || status,
  });
};
