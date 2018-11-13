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
    console.error('JSON-Schema validation failed: ' + error);
  }

  this._keyServer = options.KeyServer || "https://keyservice.microtronics.com";
  this._client = request.createClient(this._keyServer);

  this._publicKey = options.publicKey;

  //this option may be set from the outside to avoid the check of the signature part (useful for development purposes)
  this._skipVerification = options.skipVerification || false;
};

jwtDecode.prototype.verifyToken = function (token) {
  let me=this;
  return new Promise(async (resolve, reject) => {
    try {
      if (!me._publicKey)
        me._publicKey = await requestPublicKey(this._client, token);

      if (me._skipVerification)
        resolve();
      else
        resolve(await verifyToken(token, me._publicKey));
    }
    catch(err){
      reject(err);
    }
  });
};

jwtDecode.prototype.verifyRequest = function (req) {
  const me=this;
  return new Promise(async (resolve, reject) => {
    try {
      let token = parseToken(req);
      if (!token)
        return reject();
      await me.verifyToken(token);
      req._jwtPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      resolve();
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
    let header = JSON.parse(Buffer.from(tokenParts[0],'base64').toString());
    let alg = /^(ES|RS)512$/.exec(header.alg);
    if (header.typ !== "JWT" || !alg)
      return reject();

    let signature = new sshpk.Signature({
      type: (alg[1]==='ES' ? 'ed25519': 'rsa'),
      hashAlgo: 'sha512', //we're only going to support sha512
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

module.exports = jwtDecode;
