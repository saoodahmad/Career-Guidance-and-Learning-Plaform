const multer = require('multer');
const uniqid = require('uniqid');
const path = require('path');

const fileStorageEngine = multer.diskStorage({
  destination: (req, file, cb) => {
    var destinationPath = './public/';
    if (file.fieldname === 'verificationdocument') {
      destinationPath += 'files/verificationdocuments';
    } else if (file.fieldname === 'productimage') {
      destinationPath += 'images/products';
    } else {
      destinationPath += 'images/profile';
    }
    cb(null, destinationPath);
  },

  filename: (req, file, cb) => {
    cb(null, uniqid() + file.originalname);
  },
});

const fileFilter = (req, file, cb) => {
  var ext = path.extname(file.originalname);

  let Path = './public/';
  if (file.fieldname === 'verificationdocument') {
    Path += 'files/verificationdocuments';
  } else if (file.fieldname === 'productimage') {
    Path += 'images/products';
  } else {
    Path += 'images/profile';
  }

  if (file.fieldname === 'verificationdocument') {
    if (!['.pdf'].includes(ext)) {
      return cb(new Error('Only pdf is allowed'));
    }
  }
  if (file.fieldname === 'productimage') {
    if (!['.jpg', '.jpeg', '.png'].includes(ext)) {
      return cb(new Error('Only images are allowed'));
    }
  }
  if (file.fieldname === 'personalPhoto') {
    if (!['.jpg', '.jpeg', '.png'].includes(ext)) {
      return cb(new Error('Only images are allowed'));
    }
  }
  cb(null, true);
};

const upload = multer({ storage: fileStorageEngine, fileFilter: fileFilter });

exports.uploadVerificationDocument = upload.fields([
  { name: 'verificationdocument', maxCount: 1 },
]);

exports.uploadProductImage = upload.fields([
  { name: 'productimage', maxCount: 1 },
]);

exports.uploadProfileImage = upload.fields([
  { name: 'personalPhoto', maxCount: 1 },
]);
