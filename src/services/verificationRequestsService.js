const VerificationRequest = require('../models/VerificationRequestModel');

exports.getVerificationRequestByUserService = async (user) => {
  return await VerificationRequest.find({ user });
};

exports.getPendingVerificationRequestsService = async () => {
  return await VerificationRequest.find({ status: 'pending' });
};

exports.getVerificationRequestById = async (id) => {
  return await VerificationRequest.findById(id);
};

exports.updateVerificationRequestById = async (
  id,
  remark,
  status,
  approver
) => {
  return await VerificationRequest.findByIdAndUpdate(id, {
    remark,
    status,
    approver,
  });
};

exports.getVerificationRequestByIdService = async (requestID) => {
  return await VerificationRequest.findById(requestID);
};
