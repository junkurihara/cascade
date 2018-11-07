/**
 * OpenPGP default key parameters
 */

export default {
  ECC_P521_NO_EXPIRE: {
    type: 'ECC',
    curve: 'P-521',
    keyExpirationTime: 0
  },

  ECC_P256_EXPIRE_1_WEEK: {
    type: 'ECC',
    curve: 'P-256',
    keyExpirationTime: 604800 // one week just in case
  },

  SYMMETRIC_AES256_AEAD_EAX:{
    type: 'SYMMETRIC',
    length: 32, // in bytes
    algorithm: 'aes256',
    aead: true,
    aead_mode: 'eax'
  },

  DEFAULT_USER : '<example@example.com>',

  /**
   * openpgp.worker.js must be located in the place where api_openpgp.js and js-file bundling core-file.
   * Namely in this project, they are located in 'dist' and it will be './' from the viewpoint of bundled file.
    */
  WORKER_PATH_WEB: './openpgp.worker.min.js',

  WORKER_PATH_NODE: '../node_modules/openpgp/dist/openpgp.worker.min.js',

  // mapping names of curve
  CURVE_LIST: {
    'P-256': {name: 'p256'},
    'P-384': {name: 'p384'},
    'P-521': {name: 'p521'}
  }
};