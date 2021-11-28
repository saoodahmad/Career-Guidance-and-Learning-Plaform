const path = require('path');
const fileSystem = require('fs');
const ErrorResponse = require('../error-handler/errorResponse');
const User = require('../models/userModel');
const {
  getUserByIdService,
  getAllMentors,
  getMentorsByCategory,
} = require('../services/usersService');

exports.getDashboard = async (req, res, next) => {
  res.status(200).json({
    success: true,
    user: {
      name: req.user.name,
      role: req.user.role,
    },
  });
};

exports.getMyProfile = async (req, res, next) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
};

exports.getUserProfile = async (req, res, next) => {
  try {
    const { id } = req.params;

    const user = await getUserByIdService(id);

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }
    return res.status(200).json({
      success: true,
      user: user,
    });
  } catch (error) {
    next(error);
  }
};

exports.updateMyProfile = async (req, res, next) => {
  const {
    name,
    category,
    description,
    personalAddress,
    contactNumber,
    personalPhotoURL,
    academicDetail,
  } = req.body;

  console.log('req.body', req.body);
  const userID = req.user._id;

  if (
    !name ||
    !category ||
    !description ||
    !personalAddress ||
    !contactNumber ||
    !personalPhotoURL ||
    !academicDetail
  ) {
    return next(new ErrorResponse('Invalid Details', 400));
  }

  try {
    await User.findByIdAndUpdate(userID, {
      name,
      category,
      description,
      personalAddress: {
        address: personalAddress.address,
        city: personalAddress.city,
        postalCode: personalAddress.postalCode,
        country: personalAddress.country,
      },
      contactNumber,
      personalPhotoURL,
      academicDetail: {
        highestQualification: academicDetail.highestQualification,
        yearOfPassing: academicDetail.yearOfPassing,
        institution: academicDetail.institution,
      },
      isVerified: false,
    });

    return res.status(200).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};

exports.getProfileImageURL = async (req, res, next) => {
  if (!req.files.personalPhoto) {
    return next(new ErrorResponse('Please provide valid image file', 400));
  }
  if (req.files.personalPhoto[0].size > 1024 * 1024 * 5) {
    let path, error;

    path = req.files.personalPhoto[0].path;

    fileSystem.unlink(path, (err) => {
      if (err) {
        error = err;
      }
    });

    if (error) {
      return next(new ErrorResponse('Server Error', 500));
    }
    return next(new ErrorResponse('Image size exceeds 5 MB', 400));
  } else {
    res.status(201).json({
      success: true,
      personalPhotoURL: path.join(
        'images',
        'profile',
        req.files.personalPhoto[0].filename
      ),
    });
  }
};

exports.getMentorById = async (req, res, next) => {
  try {
    const { mentorID } = req.params;
    const user = await getUserByIdService(mentorID);

    if (!user) {
      return next(new ErrorResponse('Mentor Not found', 404));
    }
    const {
      _id,
      name,
      description,
      category,
      personalPhotoURL,
      academicDetail: { highestQualification },
    } = user;

    return res.status(200).json({
      success: true,
      mentor: {
        _id,
        name,
        description,
        category,
        photo: personalPhotoURL,
        qualification: highestQualification,
      },
    });
  } catch (error) {
    return next(error);
  }
};

exports.getMentors = async (req, res, next) => {
  try {
    const mentors = await getAllMentors();

    if (mentors.length === 0) {
      return next(new ErrorResponse('No Mentors Found', 404));
    }

    return res.status(200).json({
      success: true,
      mentors,
    });
  } catch (error) {
    return next(error);
  }
};

exports.getMentorsByCategory = async (req, res, next) => {
  try {
    const { category } = req.params;

    const mentors = await getMentorsByCategory(category);

    if (mentors.length === 0) {
      return next(new ErrorResponse('No Mentors Found', 404));
    }

    return res.status(200).json({
      success: true,
      mentors,
    });
  } catch (error) {
    return next(error);
  }
};
