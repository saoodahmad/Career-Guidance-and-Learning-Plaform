const jwt = require('jsonwebtoken');
const User = require('../models/userModel');

exports.getUserByEmailService = async (email) => {
  return await User.findOne({ email })
    .select('+password')
    .select('+passwordResetToken');
};

exports.getUserByIdService = async (userID) => {
  return await User.findById(userID);
};

exports.getMentorByIdService = async (mentorID) => {
  return await User.findOne({ _id: mentorID, role: 'mentor' });
};

exports.getAllMentors = async () => {
  return await User.find(
    { role: 'mentor', isVerified: true },
    {
      name: 1,
      category: 1,
      description: 1,
      personalPhotoURL: 1,
      'academicDetail.highestQualification': 1,
    }
  );
};

exports.getMentorsByCategory = async (category) => {
  return await User.find(
    { role: 'mentor', category: category, isVerifed: true },
    {
      name: 1,
      category: 1,
      description: 1,
      personalPhotoURL: 1,
      'academicDetail.highestQualification': 1,
    }
  );
};

exports.getUserFromTokenService = async (token) => {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  return await this.getUserByIdService(decoded.id);
};

exports.createUserService = async (
  email,
  password,
  role,
  passwordResetToken
) => {
  return await User.create({
    email,
    username: email,
    password,
    role,
    passwordResetToken,
  });
};

exports.updateUserService = async (id, options) => {
  return await User.findByIdAndUpdate(id, options);
};
