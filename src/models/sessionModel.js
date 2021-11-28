const mongoose = require('mongoose');

const SessionSchema = new mongoose.Schema(
  {
    menteeID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },

    mentorName: {
      type: String,
      required: true,
    },
    menteeName: {
      type: String,
      required: true,
    },
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
    category: {
      type: String,
    },
    sessionRequestID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'SessionRequest',
    },
    sessionLink: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

const Session = mongoose.model('Session', SessionSchema);

module.exports = Session;
