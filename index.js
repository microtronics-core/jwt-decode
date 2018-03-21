'use strict';

const jwt = require('jsonwebtoken');
const request = require('request-json');
const parseToken = require('parse-bearer-token');
const Validator = require('jsonschema').Validator;

const optionsSchema = {
  'type': 'object',
  'properties': {
    'KeyServer': {'type': 'string'},
    'ApplianceId': {'type': 'string'}
  },
  'required': ['KeyServer', 'ApplianceId']
};

let jwtDecode = function (options) {
  try {
    let v = new Validator();
    v.validate(options, optionsSchema, {throwError: true});
  }
  catch (error) {
    console.error('JSON-Schema validation failed: ' + error);
  }

  this._keyServer = options.KeyServer;
  this._applianceId = options.ApplianceId;

  this._client = request.createClient(options.KeyServer);
};

jwtDecode.prototype._requestPublicKey = function (onDone) {
  let path = '/api/1/keys/' + this._applianceId;
  this._client.get(path, (err, res, body) => {
    if(err) {
      console.error('Request to ' + this._keyServer + path + ' failed: ' + err);
      onDone(null);
    }
    else {
      onDone(body.PublicKey);
    }
  });
};

jwtDecode.prototype.verifyToken = function (token, onDone) {
  this._requestPublicKey((publicKey) => {
    jwt.verify(token, publicKey, (err, decoded) => {
      if(err) {
        console.error(err);
        onDone(err);
      }
      else {
        onDone(null, decoded);
      }
    });
  });
};

jwtDecode.prototype.verifyRequest = function (req, onDone) {
  this._requestPublicKey((publicKey) => {
    let token = parseToken(req);
    jwt.verify(token, publicKey, (err, decoded) => {
      if(err) {
        console.error(err);
        onDone(err);
      }
      else {
        req.decoded = decoded;
        onDone(null);
      }
    });
  });
};

//module.exports = jwtDecode;
module.exports = function (options) {
  return new jwtDecode(options);
};
