/**
 * config.js
 */

export default {
  ////////////////////////////////////////////////////////////
  publicKeyIdLEN: 32,
  publicKeyIdHash: 'SHA-256',

  ////////////////////////////////////////////////////////////
  sessionKeyIdLength: 32, // 8 byte session key id given from last 8 byte from sha 256 digest as public key id
  sessionKeyIdHash: 'SHA-256', // for hash digest of session key

  ////////////////////////////////////////////////////////////
  // Suite-specific parameters below
  ////////////////////////////////////////////////////////////
  // jscu
  jscu: {
    // iv length for AES-GCM
    ivLengthAesGcm: 12,
  },

  ////////////////////////////////////////////////////////////
};
