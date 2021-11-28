const mongoose = require('mongoose');

const VerificationRequestSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },

    status: {
      type: String,
      default: 'pending',
    },
    // approved: {
    //   type: Boolean,
    //   required: true,
    //   default: false,
    // },
    remark: {
      type: String,
      default: null,
    },
    // closed: {
    //   type: Boolean,
    //   default: false,
    // },
    approver: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    verificationDocumentURL: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

const VerificationRequest = mongoose.model(
  'VerificationRequest',
  VerificationRequestSchema
);

module.exports = VerificationRequest;
