const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const ReviewSchema = new mongoose.Schema(
  {
    menteeID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    mentorID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    menteeName: {
      type: String,
      required: true,
    },
    comment: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);
const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Please provide username'],
    },
    email: {
      type: String,
      required: [true, 'Please provide valid email'],
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'please provide a valid email',
      ],
      unique: true,
    },

    reviews: [ReviewSchema],
    name: {
      type: String,
      default: '',
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: [6, 'Minimum length of password should be 6'],
      select: false, // exclude password field by default while responding to query on user
    },
    passwordResetToken: {
      type: String,
      required: [true, 'Please provide a password reset token'],
      minlength: [12, 'Minimum length of password rest token should be 6'],
      select: false,
    },
    category: {
      type: String,
      default: null,
    },
    description: {
      type: String,
      default: 'Not Provided',
    },
    role: {
      type: String,
      required: [true, 'Please provide a role'],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isDisabled: {
      type: Boolean,
      default: false,
    },

    personalAddress: {
      address: {
        type: String,
        default: '',
      },
      city: {
        type: String,
        default: '',
      },
      postalCode: {
        type: String,
        default: '',
      },
      country: {
        type: String,
        default: 'India',
      },
    },
    contactNumber: {
      type: String,
      default: '',
    },
    personalPhotoURL: {
      type: String,
      default: 'images/profile/1633095121436personalPhoto.png',
    },
    academicDetail: {
      highestQualification: {
        type: String,
        default: '',
      },
      yearOfPassing: {
        type: String,
        default: '',
      },
      institution: {
        type: String,
        default: '',
      },
    },
  },
  {
    timestamps: true,
  }
);

// to hash password before saving to database
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// to hash password reset token before saving to database
UserSchema.pre('save', async function (next) {
  const salt = await bcrypt.genSalt(10);
  this.passwordResetToken = await bcrypt.hash(this.passwordResetToken, salt);
  next();
});

// to verify the password provided duirng login
UserSchema.methods.matchPasswords = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// to verify the password reset token provided during password reset
UserSchema.methods.matchPasswordResetToken = async function (
  passwordResetToken
) {
  console.log(passwordResetToken);
  return await bcrypt.compare(passwordResetToken, this.passwordResetToken);
};

// to generate jwt tokens
UserSchema.methods.getSignedToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

const User = mongoose.model('User', UserSchema);

module.exports = User;
