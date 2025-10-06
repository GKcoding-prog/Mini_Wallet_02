const crypto = require('crypto');

const algorithm = 'aes-256-cbc';

function encryptData(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
}

function decryptData(encryptedObject, key) {
  if (!encryptedObject || typeof encryptedObject !== 'object') {
    throw new Error('encryptedObject must be a valid object');
  }

  const iv = Buffer.from(encryptedObject.iv, 'hex');
  const encrypted = encryptedObject.encryptedData || encryptedObject.data; // Supporte encryptedData ou data comme fallback
  if (!encrypted) {
    throw new Error('encryptedData or data field is missing');
  }

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encryptData, decryptData };