const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const ivLength = 16;

function encryptData(data, key) {
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

function decryptData(encryptedObj, key) {
  const iv = Buffer.from(encryptedObj.iv, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedObj.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encryptData, decryptData };