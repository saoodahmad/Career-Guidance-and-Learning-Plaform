const Session = require('../models/sessionModel');

exports.getSessionsInATimeRange = async (fields) => {
  let Start = new Date(fields.start);
  let End = new Date(fields.end);
  console.log(Start, End);
  return await Session.find({
    $and: [
      {
        $or: [
          { end: { $gte: Start, $lte: End } },
          { start: { $gte: Start, $lte: End } },
          {
            $and: [{ start: { $lt: Start } }, { end: { $gt: End } }],
          },
        ],
      },
      { mentorID: fields.mentorID },
    ],
  });
};

exports.createSession = async (fields) => {
  return await Session.create({ ...fields });
};

exports.getMySessionsInADateRange = async (userID, role, start, end) => {
  if (role === 'mentor') {
    const sessions = await Session.find({
      mentorID: userID,
      start: { $gte: start, $lte: end },
    });

    return sessions;
  }
  if (role === 'mentee') {
    const sessions = await Session.find({
      menteeID: userID,
      start: { $gte: start, $lte: end },
    });

    return sessions;
  }
};
