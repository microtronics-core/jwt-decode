'use strict';

let jwt = require('jsonwebtoken');

let jwtDecode = function (options) {
  console.log(options);

  //todo: get some parameter like keyserver etc.
  //todo: verify token/complete request with info from keyservice ...
};

jwtDecode.prototype.verifyToken = function (token, publicKey) {
  let decoded = '';
  try {
    decoded = jwt.verify(token, publicKey);
  }
  catch(err) {
    console.error(err);
  }

  console.log(decoded);

  return decoded;
};

//module.exports = jwtDecode;
module.exports = function (options) {
  return new jwtDecode(options);
};
