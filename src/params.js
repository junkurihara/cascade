/**
 * params.js
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
  // OpenPGP
  openpgp : {
    defaultUser : '<example@example.com>',

    // openpgp.worker.js must be located in the place where api_openpgp.js and js-file bundling core-file.
    // Namely in this project, they are located in 'dist' and it will be './' from the viewpoint of bundled file.
    workerPathWeb: './openpgp.worker.min.js',

    workerPathNode: '../node_modules/openpgp/dist/openpgp.worker.min.js',

    // mapping names of curve
    curveList: {
      'P-256': {name: 'p256'},
      'P-384': {name: 'p384'},
      'P-521': {name: 'p521'}
    }
  }
};