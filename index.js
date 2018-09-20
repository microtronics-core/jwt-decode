'use strict';

const request = require('request-json');
const parseToken = require('parse-bearer-token');
const Validator = require('jsonschema').Validator;
const sshpk = require('sshpk');

const optionsSchema = {
  'type': 'object',
  'properties': {
    'KeyServer': {'type': 'string'}
  }
};

let jwtDecode = function (options) {
  try {
    let v = new Validator();
    v.validate(options, optionsSchema, {throwError: true});
  }
  catch (error) {
    console.error('JSON-Schema validation failed: ' + error); //TODO: throw error???
  }

  this._keyServer = options.KeyServer || "https://keyservice.microtronics.com";

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
    let payload = JSON.parse(new Buffer(token.split('.')[1], 'base64'));
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
    let pubKey=new sshpk.Key({
      type: 'ed25519',
      parts: [
        { name: 'A', data: Buffer.from(publicKey, 'hex')}
      ]
    });
    let tokenParts=token.split('.');
    let signature = new sshpk.Signature({
      type: 'ed25519',
      hashAlgorithm: 'sha512',
      parts: [
        { name: 'sig', data: Buffer.from(tokenParts[2], 'base64')}
      ]
    });
    let verifier=pubKey.createVerify();
    verifier.update(`${tokenParts[0]}.${tokenParts[1]}`);
    if (verifier.verify(signature)) {
      resolve();
    } else {
      reject();
    }
  });
}

//module.exports = jwtDecode;
module.exports = function (options) {
  return new jwtDecode(options);
};
