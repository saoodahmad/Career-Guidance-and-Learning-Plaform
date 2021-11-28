const mongoose = require('mongoose');

const SessionRequestSchema = new mongoose.Schema(
  {
    menteeID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    menteeName: {
      type: String,
      required: true,
    },
    mentorName: { type: String, required: true },
    mentorID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    start: {
      type: Date,
    },
    duration: {
      type: Number,
    },
    end: {
      type: Date,
    },
    status: {
      type: String,
      default: 'pending',
    },
    subject: {
      type: String,
    },
    category: {
      type: String,
    },
    sessionID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Session',
    },
    remark: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

const SessionRequest = mongoose.model('SessionRequest', SessionRequestSchema);

module.exports = SessionRequest;
