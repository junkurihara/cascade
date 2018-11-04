export default {
  procedure: [
    // keyParams is set for steps that involves automatic key generation.

    // first step that encrypts the given data
    // non-last step generates key automatically on site.
    // final step that encrypts the key used in the previous step under the given original key.
    // last step feeds the given key.
    {
      encrypt: {
        suite: 'openpgp',
        options: {
          detached: false, // for signing simultaneously with encryption
          compression: 'zlib'
        },
        output: 'armored'
      },
      sign: {
        required: true,
        suite: 'openpgp',
        options: { }
      }
      // keyParams is unnecessary to be set. key params will be ignored at last step.
    } // -> output "encrypted decryption key for 2", "key id for 2"
  ],

  // output format
  'output': 'json'
};
