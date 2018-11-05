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
  const userIds = [ 'test@example.com' ];
  const Keys={};
  const KeysGPG={};
  let message;
  const paramArray = [{name: 'EC', param: curves}, {name: 'RSA', param: modulusLength}];

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    Keys.EC = await Promise.all(
      curves.map ( (curve) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'ECC', curve}}))
    );
    KeysGPG.EC = await Promise.all(
      curves.map ( (curve) => cascade.generateKey({suite: 'openpgp', userIds, keyParams: {type: 'ECC', keyExpirationTime: 0, curve}}))
    );
    Keys.RSA = await Promise.all(
      modulusLength.map ( (ml) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'RSA', modulusLength: ml}}))
    );
    KeysGPG.RSA = await Promise.all(
      modulusLength.map ( (ml) => cascade.generateKey({suite: 'openpgp', userIds, keyParams: {type: 'RSA', keyExpirationTime: 0, modulusLength: ml}}))
    );
  });

  it('jscu: EC/RSA encryption test', async () => {
    await Promise.all(paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [ Keys[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey: Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = {
          encrypt: {
            suite: 'jscu',
            options:
              (paramObject.name === 'EC')
                ? { privateKeyPass: { privateKey: Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' }, // only for ECDH
                  hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: '' }
                : {hash: 'SHA-256'},
          },
          sign: { required: true, suite: 'jscu',
            options: (paramObject.name === 'EC') ? {hash: 'SHA-256'} : {hash: 'SHA-256', name: 'RSA-PSS', saltLength: 32},
          } // optional sign
        };
        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey: Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
          publicKeys: [ Keys[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });

  it('openpgp: RSA/EC encryption test', async () => {

    await Promise.all(paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [ KeysGPG[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey: KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = {
          encrypt: { suite: 'openpgp', options: { detached: true, compression: 'zlib' }},
          sign: {required: true, suite: 'openpgp', options: {}} // optional sign
        };
        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey: KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
          publicKeys: [ KeysGPG[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });


  // it('mix1 (encrypt: openpgp, sign: jscu): EC encryption test', async () => {
  //   await Promise.all( curves.map( async( curve, idx) => {
  //     const encryptionKeys = {
  //       publicKeys: [ ECKeysGPG[idx].publicKey.keyString ],
  //       privateKeyPassSets:[ { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' } ] // for Signing
  //     };
  //     const encryptConfig = {
  //       encrypt: { suite: 'openpgp', options: { detached: true, compression: 'zlib' } },
  //       sign: { required: true, suite: 'jscu', options: {hash: 'SHA-256'} } // optional sign
  //     };
  //     const encryptionKeyImported = await cascade.importKeys(
  //       'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
  //     );
  //     const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig });
  //
  //     const decryptionKeys = {
  //       privateKeyPassSets:[ { privateKey: ECKeysGPG[idx].privateKey.keyString, passphrase: '' } ],
  //       publicKeys: [ ECKeys[idx].publicKey.keyString ] // for verification
  //     };
  //     const decryptionKeyImported = await cascade.importKeys(
  //       'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
  //     ).catch(e => console.error(e));
  //     const decryptionResult = await cascade.decrypt({data: encryptionResult, keys: decryptionKeyImported});
  //     expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
  //   }));
  // });
  //
  //
  // it('mix2 (encrypt: jscu, sign: openpgp): EC encryption test', async () => {
  //   await Promise.all( curves.map( async(curve, idx) => {
  //     const encryptionKeys = {
  //       publicKeys: [ ECKeys[idx].publicKey.keyString ],
  //       privateKeyPassSets:[ { privateKey: ECKeysGPG[idx].privateKey.keyString, passphrase: '' } ] // for Signing
  //     };
  //     const encryptConfig = {
  //       encrypt: {
  //         suite: 'jscu',
  //         options: {
  //           privateKeyPass: { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' }, // only for ECDH
  //           hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: ''
  //         }, // optional sign
  //       },
  //       sign: {required: true, suite: 'openpgp', options: {}} // optional sign
  //     };
  //     const encryptionKeyImported = await cascade.importKeys(
  //       'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
  //     );
  //     const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig });
  //
  //     const decryptionKeys = {
  //       privateKeyPassSets:[ { privateKey: ECKeys[idx].privateKey.keyString, passphrase: '' } ],
  //       publicKeys: [ ECKeysGPG[idx].publicKey.keyString ] // for verification
  //     };
  //     const decryptionKeyImported = await cascade.importKeys(
  //       'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'openpgp'}, mode: ['decrypt', 'verify']}
  //     ).catch(e => console.error(e));
  //     const decryptionResult = await cascade.decrypt({data: encryptionResult, keys: decryptionKeyImported});
  //     expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
  //   }));
  // });


  // TODO: symmetric (with and without sign)
  // TODO: only encrypt
  // TODO: onnly sign

});