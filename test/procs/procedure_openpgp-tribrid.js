import openpgpDefault from '../../src/params_openpgp.js';

// 配列にして前から順番にgiven dataにアプライ、最後に与えられた鍵で前の要素の鍵(or data)を暗号化
export default {
  procedure: [
    // keyParams is set for steps that involves automatic key generation.

    // first step that encrypts the given data
    // non-last step generates key automatically on site.
    {
      encrypt: {
        suite: 'openpgp',  // 'jscu'
        keyParams: openpgpDefault.ECC_P521_NO_EXPIRE, // default algorithms like ecc, 1: this key encrypts data
        options: {
          detached: false,
          compression: 'zlib',
          output: 'armored' // or 'binary'
        }
      },
      sign: {
        required: true,
        options: {
          output: 'armored' // or 'binary'
        }
      }
    }, // -> output "encrypted data" "key id"


    // second step that encrypts the key used in the first step under auto-generated key.
    {
      encrypt: {
        suite: 'openpgp',// 'jscu'
        keyParams: openpgpDefault.SYMMETRIC_AES256_AEAD_EAX, // default algorithms like ecc, 2: this key encrypts step 1 key
        options: {
          detached: false,
          compression: 'zlib'
        },
        output: 'armored' // or 'binary'
      },
      sign: {
        required: true,
        options: { },
        output: 'armored' // or 'binary'
      }
    }, // -> output "encrypted decryption key for 1", "key id for 1"


    // final step that encrypts the key used in the previous step under the given original key.
    // last step feeds the given key.
    {
      encrypt: {
        suite: 'openpgp',  // 'jscu'
        options: {
          detached: true, // for signing simultaneously with encryption
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
    } // -> output "encrypted decryption key for 2", "key id for 2"
  ],

  // output format
  'output': 'json'
};
