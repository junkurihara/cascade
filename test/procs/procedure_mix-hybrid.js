import jscuDefault from '../../src/params_jscu.js';

// 配列にして前から順番にgiven dataにアプライ、最後に与えられた鍵で前の要素の鍵(or data)を暗号化
export default {
  procedure: [
    // keyParams is set for steps that involves automatic key generation.
    // first step that encrypts the given data
    // non-last step generates key automatically on site.
    {
      // /*
      encrypt: {
        suite: 'jscu',
        keyParams: jscuDefault.SYMMETRIC_AES256_GCM,
        options: {},
        output: 'binary'
      },
      sign: {
        required: true,
        output: 'binary'
      }
    }, // -> output "encrypted data" "key id"

    // final step that encrypts the key used in the previous step under the given original key.
    // last step feeds the given key.
    {
      encrypt: {
        suite: 'openpgp',  // 'jscu'
        options: {
          detached: true, // for signing simultaneously with encryption
          compression: 'zlib'
        },
        output: 'armored'
      },
      sign: {
        required: true,
        suite: 'jscu',
        options: jscuDefault.ECDSA_SHA_256,
        output: 'binary'
      }
      // keyParams is unnecessary to be set. key params will be ignored at last step.
    } // -> output "encrypted decryption key for 2", "key id for 2"
  ],

  // output format
  'output': 'json'
};
