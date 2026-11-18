const crypto = require('crypto');

// Store a keyed digest of the request IP, browser agent, and hashed browser token.
function fingerprintForRequest(req, deviceToken = '') {
  const forwarded = req.get?.('x-forwarded-for') || req.headers?.['x-forwarded-for'];
  const trustedForwardedIp = process.env.TRUST_PROXY === 'true' && forwarded ? String(forwarded).split(',')[0].trim() : '';
  const ip = String(trustedForwardedIp || req.ip || req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
  const agent = String(req.get?.('user-agent') || req.headers?.['user-agent'] || '').slice(0, 300);
  const secret = process.env.FINGERPRINT_SECRET;
  if (!secret || secret.length < 32) throw new Error('FINGERPRINT_SECRET must contain at least 32 characters.');
  const device = String(deviceToken || '').slice(0, 128);
  return crypto.createHmac('sha256', secret).update(`${ip}\n${agent}\n${device}`).digest('hex');
}

// Hash access codes and staff secrets so the database stores no usable code.
function hashSecret(value) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters.');
  return crypto.createHmac('sha256', secret).update(String(value)).digest('hex');
}

// Hash the random browser token before it can enter the server-side session store.
function hashDeviceToken(value) {
  const secret = process.env.FINGERPRINT_SECRET;
  if (!secret || secret.length < 32) throw new Error('FINGERPRINT_SECRET must contain at least 32 characters.');
  return crypto.createHmac('sha256', secret).update(String(value)).digest('hex');
}

module.exports = { fingerprintForRequest, hashSecret, hashDeviceToken };
