const ErrorResponse = require('../error-handler/errorResponse');

const {
  getUserByEmailService,
  createUserService,
} = require('../services/usersService');

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await getUserByEmailService(email);

    if (!user) {
      return next(new ErrorResponse('User does not exist', 404));
    }

    const isMatch = await user.matchPasswords(password);

    if (!isMatch) {
      return next(new ErrorResponse('Incorrect email or password ', 400));
    }

    return res.status(200).json({
      success: true,
      token: user.getSignedToken(),
    });
  } catch (error) {
    return next(error);
  }
};

exports.register = async (req, res, next) => {
  try {
    const { email, password, confirmPassword, role, passwordResetToken } =
      req.body;
    if (
      !email ||
      !password ||
      !confirmPassword ||
      !role ||
      !passwordResetToken
    ) {
      return next(new ErrorResponse('Invalid credentials', 400));
    }

    const user = await getUserByEmailService(email);

    if (user) {
      return next(new ErrorResponse('User already exists', 400));
    }

    if (password != confirmPassword) {
      return next(
        new ErrorResponse('Password and Confirm Password do not match')
      );
    }

    const validRoles = ['mentor', 'mentee'];

    if (!validRoles.includes(role)) {
      return next(new ErrorResponse('Please provide valid role', 400));
    }
    const newUser = await createUserService(
      email,
      password,
      role,
      passwordResetToken
    );

    return res.status(201).json({
      success: true,
      token: newUser.getSignedToken(),
    });
  } catch (error) {
    return next(error);
  }
};

exports.registerAdmin = async (req, res, next) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      return next(new ErrorResponse('Invalid credentials', 400));
    }
    const user = await getUserByEmailService(email);

    if (user) {
      return next(new ErrorResponse('User already exists', 400));
    }

    if (password != confirmPassword) {
      return next(
        new ErrorResponse('Password and Confirm Password do not match')
      );
    }

    const newUser = await createUserService(
      email,
      password,
      'admin',
      process.env.PASSWORD_RESET_TOKEN_DEFAULT // default password reset token token
    );

    return res.status(201).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};

exports.resetPassword = async (req, res, next) => {
  try {
    const { email, newPassword, confirmNewPassword, passwordResetToken } =
      req.body;

    if ((!email, !newPassword || !confirmNewPassword || !passwordResetToken)) {
      return next(new ErrorResponse('Invalid credentials', 400));
    }

    if (newPassword != confirmNewPassword) {
      return next(
        new ErrorResponse('New Password and Confirm New Password do not match')
      );
    }

    const user = await getUserByEmailService(email);

    if (!user) {
      return next(new ErrorResponse('Invalid Credentials', 400));
    }

    const isMatch = await user.matchPasswordResetToken(passwordResetToken);

    if (!isMatch) {
      return next(new ErrorResponse('Invalid credentials', 400));
    }

    user.password = newPassword;
    user.save();

    return res.status(200).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};

exports.updatePassword = async (req, res, next) => {
  try {
    const { email, existingPassword, newPassword, confirmNewPassword } =
      req.body;

    if ((!email, !newPassword || !confirmNewPassword || !existingPassword)) {
      return next(new ErrorResponse('Invalid credentials', 400));
    }

    if (newPassword != confirmNewPassword) {
      return next(
        new ErrorResponse('New Password and Confirm New Password do not match')
      );
    }

    const user = await getUserByEmailService(email);

    if (!user) {
      return next(new ErrorResponse('Invalid Credentials', 400));
    }

    const isMatch = await user.matchPasswords(existingPassword);

    if (!isMatch) {
      return next(new ErrorResponse('Invalid credentials', 400));
    }

    user.password = newPassword;
    user.save();

    return res.status(200).json({
      success: true,
    });
  } catch (error) {
    return next(error);
  }
};
