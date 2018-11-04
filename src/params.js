/**
 * params.js
 */

import openpgpParams from './params_openpgp.js';

export default {
  ////////////////////////////////////////////////////////////
  publicKeyIdLEN: 32,
  publicKeyIdHash: 'SHA-256',

  ////////////////////////////////////////////////////////////
  sessionKeyIdLength: 32, // 8 byte session key id given from last 8 byte from sha 256 digest as public key id
  sessionKeyIdHash: 'SHA-256', // for hash digest of session key

  ////////////////////////////////////////////////////////////
  defaultEncryptConfig: {
    encrypt: {
      suite: 'openpgp',  // 'jscu'
      options: {
        detached: true,
        compression: 'zlib'
      },
      output: 'armored' // or 'binary'
    },
    sign: {
      required: true,
      suite: 'openpgp', // 'jscu'
      options: { },
      output: 'armored' // or 'binary'
    }
  },
  ////////////////////////////////////////////////////////////
  defaultProcedure: [
    // keyParams is set for steps that involves automatic key generation.

    // first step that encrypts the given data
    // non-last step generates key automatically on site.
    {
      encrypt: {
        suite: 'openpgp',// 'jscu'
        keyParams: openpgpParams.SYMMETRIC_AES256_AEAD_EAX, // default algorithms like ecc, 2: this key encrypts step 1 key
        options: {
          detached: false,
          compression: 'zlib'
        },
        output: 'armored' // or 'binary'
      },
      sign: {
        required: true,
        options: {},
        output: 'armored' // or 'binary'
      }
    }, // -> output "encrypted data" "key id"


    // final step that encrypts the key used in the previous step under the given original key.
    // last step feeds the given key.
    {
      encrypt: {
        suite: 'openpgp',  // 'jscu'
        options: {
          detached: false, // for signing simultaneously with encryption
          compression: 'zlib'
        },
        output: 'armored' // or 'binary'
      },
      sign: {
        required: true,
        suite: 'openpgp', // 'jscu'
        options: { },
        output: 'armored' // or 'binary'
      }
      // keyParams is unnecessary to be set. key params will be ignored at last step.
    } // -> output "encrypted decryption key for 1", "key id for 1"
  ],
};