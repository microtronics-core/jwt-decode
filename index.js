'use strict';

const jwt = require('jsonwebtoken');
const request = require('request-json');
const parseToken = require('parse-bearer-token');
const Validator = require('jsonschema').Validator;

const optionsSchema = {
  'type': 'object',
  'properties': {
    'KeyServer': {'type': 'string'}
  },
  'required': ['KeyServer']
};

let jwtDecode = function (options) {
  try {
    let v = new Validator();
    v.validate(options, optionsSchema, {throwError: true});
  }
  catch (error) {
    console.error('JSON-Schema validation failed: ' + error); //TODO: throw error???
  }

  this._keyServer = options.KeyServer;

  this._client = request.createClient(options.KeyServer);
};

jwtDecode.prototype.verifyToken = function (token) {
  return new Promise(async (resolve, reject) => {
    try {
      let publicKey = await requestPublicKey(this._client, token);
      resolve(await verifyToken(token, publicKey));
    }
    catch(err){
      reject(err);
    }
  });
};

jwtDecode.prototype.verifyRequest = function (req) {
  return new Promise(async (resolve, reject) => {
    try {
      let token = parseToken(req);
      let publicKey = await requestPublicKey(this._client, token);
      let decoded = await verifyToken(token, publicKey);
      req.decoded = decoded;
      resolve(decoded);
    }
    catch(err) {
      reject(err);
    }
  });
};

function requestPublicKey(client, token) {
  return new Promise((resolve, reject) => {
    let payload = JSON.parse(new Buffer(token.substring(token.indexOf('.') + 1, token.lastIndexOf('.')), 'base64'));
    let path = '/api/1/keys/' + payload.orig;   // payload.orig = applianceid
    client.get(path, (err, res, body) => {
      if(err)
        reject(err);
      else
        resolve(body.PublicKey);
    });
  });
}

function verifyToken(token, publicKey) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, Buffer.from(publicKey, 'base64'), (err, decoded) => {
      if (err)
        reject(err);
      else
        resolve(decoded);
    });
  });
}

//module.exports = jwtDecode;
module.exports = function (options) {
  return new jwtDecode(options);
};
