import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

describe(`${env}: single public key encryption/decryption`, () => {
  const curves = [ 'P-256', 'P-384', 'P-521' ];
  const modulusLength = [ 2048 ];
  const userIds = [ 'kurihara@ieee.org' ];
  let ECKeys;
  let ECKeysGPG;
  let RSAKeys;
  let RSAKeysGPG;
  let message;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    ECKeys = await Promise.all(
      curves.map ( (curve) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'ECC', curve}}))
    );
    ECKeysGPG = await Promise.all(
      curves.map ( (curve) => cascade.generateKey({suite: 'openpgp', userIds, keyParams: {type: 'ECC', keyExpirationTime: 0, curve}}))
    );
    /*
    RSAKeys = await Promise.all(
      modulusLength.map ( (ml) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'RSA', modulusLength: ml}}))
    );
    RSAKeysGPG = await Promise.all(
      modulusLength.map ( (ml) => cascade.generateKey({suite: 'openpgp', userIds, keyParams: {type: 'RSA', keyExpirationTime: 0, modulusLength: ml}}))
    );
    */
  });

  it('jscu: EC encryption test', async () => {
    await Promise.all(curves.map( async (curve, idx) => {
      const encryptionKeys = {
        publicKeys: [ ECKeys[idx].publicKey.keyString ],
        privateKeyPassSets:[ { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' } ] // for Signing
      };
      const encryptConfig = {
        encrypt: {
          suite: 'jscu',
          options: {
            privateKeyPass: { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' }, // only for ECDH
            hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: ''
          }, // optional sign
        },
        sign: {required: true, suite: 'jscu', options: {hash: 'SHA-256'}} // optional sign
      };
      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
      );
      const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

      const decryptionKeys = {
        privateKeyPassSets:[ { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' } ],
        publicKeys: [ ECKeys[idx].publicKey.keyString ] // for verification
      };
      const decryptionKeyImported = await cascade.importKeys(
        'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
      );
      const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
      expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
    }));
  });

  it('openpgp: encryption test', async () => {
    await Promise.all(curves.map( async (curve, idx) => {
      const encryptionKeys = {
        publicKeys: [ ECKeysGPG[idx].publicKey.keyString ],
        privateKeyPassSets:[ { privateKey: ECKeysGPG[idx].privateKey.keyString, passphrase: '' } ] // for Signing
      };
      const encryptConfig = {
        encrypt: { suite: 'openpgp', options: { detached: true, compression: 'zlib' }},
        sign: {required: true, suite: 'openpgp', options: {}} // optional sign
      };
      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
      );
      const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig });

      const decryptionKeys = {
        privateKeyPassSets:[ { privateKey: ECKeysGPG[idx].privateKey.keyString, passphrase: '' } ],
        publicKeys: [ ECKeysGPG[idx].publicKey.keyString ] // for verification
      };
      const decryptionKeyImported = await cascade.importKeys(
        'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['decrypt', 'verify']}
      );
      const decryptionResult = await cascade.decrypt({data: encryptionResult, keys: decryptionKeyImported});
      expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
    }));
  });


  it('mix1 (encrypt: openpgp, sign: jscu): encryption test', async () => {
    await Promise.all( curves.map( async( curve, idx) => {
      const encryptionKeys = {
        publicKeys: [ ECKeysGPG[idx].publicKey.keyString ],
        privateKeyPassSets:[ { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' } ] // for Signing
      };
      const encryptConfig = {
        encrypt: { suite: 'openpgp', options: { detached: true, compression: 'zlib' } },
        sign: { required: true, suite: 'jscu', options: {hash: 'SHA-256'} } // optional sign
      };
      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
      );
      const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig });

      const decryptionKeys = {
        privateKeyPassSets:[ { privateKey: ECKeysGPG[idx].privateKey.keyString, passphrase: '' } ],
        publicKeys: [ ECKeys[idx].publicKey.keyString ] // for verification
      };
      const decryptionKeyImported = await cascade.importKeys(
        'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
      ).catch(e => console.error(e));
      const decryptionResult = await cascade.decrypt({data: encryptionResult, keys: decryptionKeyImported});
      expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
    }));
  });


  it('mix2 (encrypt: jscu, sign: openpgp): encryption test', async () => {
    await Promise.all( curves.map( async(curve, idx) => {
      const encryptionKeys = {
        publicKeys: [ ECKeys[idx].publicKey.keyString ],
        privateKeyPassSets:[ { privateKey: ECKeysGPG[idx].privateKey.keyString, passphrase: '' } ] // for Signing
      };
      const encryptConfig = {
        encrypt: {
          suite: 'jscu',
          options: {
            privateKeyPass: { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' }, // only for ECDH
            hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: ''
          }, // optional sign
        },
        sign: {required: true, suite: 'openpgp', options: {}} // optional sign
      };
      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
      );
      const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig });

      const decryptionKeys = {
        privateKeyPassSets:[ { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' } ],
        publicKeys: [ ECKeysGPG[idx].publicKey.keyString ] // for verification
      };
      const decryptionKeyImported = await cascade.importKeys(
        'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'openpgp'}, mode: ['decrypt', 'verify']}
      ).catch(e => console.error(e));
      const decryptionResult = await cascade.decrypt({data: encryptionResult, keys: decryptionKeyImported});
      expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
    }));
  });


  // TODO: symmetric (with and without sign)
  // TODO: only encrypt
  // TODO: onnly sign

});