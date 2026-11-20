require('dotenv').config();
const { hashSecret } = require('../src/security/fingerprint');
const code = process.argv[2];
if (!code || code.length < 8) {
  console.error('Pass a staff portal access code of at least 8 characters in quotes.');
  process.exit(1);
}
console.log(hashSecret(code));
