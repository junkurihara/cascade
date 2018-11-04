/**
 * JSCU default key parameters
 */

export default {
  ECDSA_SHA_256: {
    type: 'ECC',
    hash: 'SHA-256'
  },

  JWK_KEYID_LEN: 32,
  JWK_KEYID_HASH: 'SHA-256',

  SYMMETRIC_AES256_GCM: {
    type: 'SYMMETRIC',
    algorithm: 'AES-GCM',
    length: 32
  },

  RECOMMENDED_IV_LENGTH: 12,
};