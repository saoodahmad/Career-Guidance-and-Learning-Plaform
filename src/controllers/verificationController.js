const path = require('path');
const fileSystem = require('fs');
const ErrorResponse = require('../error-handler/errorResponse');
const VerificationRequest = require('../models/VerificationRequestModel');
const {
  getVerificationRequestByUserService,
  getPendingVerificationRequestsService,
  getVerificationRequestById,
  updateVerificationRequestById,
  getVerificationRequestByIdService,
} = require('../services/verificationRequestsService');
const {
  updateUserService,
  approveUserService,
} = require('../services/usersService');

exports.getVerificationDocumentURL = async (req, res, next) => {
  if (!req.files.verificationdocument) {
    return next(new ErrorResponse('Please provide valid pdf file', 400));
  }
  if (req.files.verificationdocument[0].size > 1024 * 1024 * 20) {
    let path, error;

    path = req.files.verificationdocument[0].path;

    await fileSystem.unlink(path, (err) => {
      if (err) {
        error = err;
      }
    });

    if (error) {
      return next(new ErrorResponse('Server Error', 500));
    }
    return next(new ErrorResponse('Pdf size exceeds 20 MB', 400));
  } else {
    return res.status(201).json({
      success: true,
      verificationDocumentURL: path.join(
        'files',
        'verificationdocuments',
        req.files.verificationdocument[0].filename
      ),
    });
  }
};

exports.createVerificationRequest = async (req, res, next) => {
  try {
    const userID = req.user._id;

    const { verificationDocumentURL } = req.body;

    const verificationRequest = await VerificationRequest.findOne({
      user: userID,
      status: 'pending',
    });

    if (verificationRequest) {
      return next(
        new ErrorResponse('Verification request already underway', 400)
      );
    }

    if (req.user.isVerified) {
      return next(new ErrorResponse('Already Verified', 400));
    }

    const newVerificationRequest = await VerificationRequest.create({
      user: userID,
      verificationDocumentURL,
    });

    res.status(201).json({
      success: true,
      verificationRequest: newVerificationRequest,
    });
  } catch (error) {
    return next(error);
  }
};

exports.getMyVerificationRequests = async (req, res, next) => {
  try {
    const user = req.user._id;

    const verificationRequests = await getVerificationRequestByUserService(
      user
    );

    if (!verificationRequests || verificationRequests.length == 0) {
      return next(new ErrorResponse('No Request Found', 404));
    }

    return res.status(200).json({
      success: true,
      verificationRequests,
    });
  } catch (error) {
    return next(error);
  }
};

exports.getPendingVerificationRequests = async (req, res, next) => {
  try {
    const verificationRequests = await getPendingVerificationRequestsService();

    if (!verificationRequests || verificationRequests.length == 0) {
      return next(new ErrorResponse('No Pending Found', 404));
    }

    return res.status(200).json({
      success: true,
      verificationRequests,
    });
  } catch (error) {
    return next(error);
  }
};

exports.approveVerificationRequest = async (req, res, next) => {
  try {
    const { remark, _id: requestID } = req.body;

    const approver = req.user._id;

    const verificationRequest = await getVerificationRequestById(requestID);

    if (!verificationRequest) {
      return next(new ErrorResponse('Request Not Found', 404));
    }

    await updateVerificationRequestById(
      requestID,
      remark || 'No remark',
      'approved',
      approver
    );

    const { user: userID } = await getVerificationRequestByIdService(requestID);

    await updateUserService(userID, { isVerified: true });

    return res.status(200).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};

exports.rejecteVerificationRequest = async (req, res, next) => {
  try {
    const { remark, _id } = req.body;

    const verificationRequest = await getVerificationRequestById(_id);

    if (!verificationRequest) {
      return next(new ErrorResponse('Request Not Found', 404));
    }

    await updateVerificationRequestById(_id, remark || 'No remark', 'rejected');

    return res.status(200).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};
