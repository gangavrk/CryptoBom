// Sample for cryptobom regression testing (Node.js crypto + crypto-js).
const crypto = require('crypto');
const CryptoJS = require('crypto-js');

function weakAndMisused(key, iv, data) {
  // Weak hashes and a classic ECB misuse.
  const md5 = crypto.createHash('md5');
  const sha1 = crypto.createHmac('sha1', key);
  const ecb = crypto.createCipheriv('aes-128-ecb', key, iv);
  const des = crypto.createCipheriv('des-ede3-cbc', key, iv);

  // crypto-js
  const h = CryptoJS.MD5(data);
  const c = CryptoJS.DES.encrypt(data, key);
  const e = CryptoJS.AES.encrypt(data, key, { mode: CryptoJS.mode.ECB });
}

function vulnerable(cb) {
  // Quantum-vulnerable key generation.
  crypto.generateKeyPair('rsa', { modulusLength: 2048 }, cb);
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  crypto.generateKeyPairSync('ed25519');
}

function strong(data) {
  // Good usage — must NOT be flagged.
  const sha256 = crypto.createHash('sha256');
  const gcm = crypto.createCipheriv('aes-256-gcm', key, iv);
}
