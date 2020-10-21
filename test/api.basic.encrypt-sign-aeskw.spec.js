import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import {createParam} from './params-basic.js';

describe(`${env}: single public key wrapping/unwrapping with simultaneous signing/verification`, () => {

  let message;
  let param;

  beforeAll(async () => {
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  },50000);

  it('jscu: ECDH KeyWrapping and signing test',  async () => {
    const paramObject = param.paramArray[0];

    await Promise.all(paramObject.param.map( async (p, idx) => {
      const encryptionKeys = {
        publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ],
        privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
      };
      const encryptConfig = { encrypt: param.jscuKeyWrappingConf(paramObject, idx), sign: param.jscuSignConf(paramObject) };

      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
      );
      const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});
      // console.log(encryptionResult);

      const decryptionKeys = {
        privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
        publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ] // for verification
      };
      const decryptionKeyImported = await cascade.importKeys(
        'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
      );
      const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
      expect(decryptionResult.signatures.every((s) => s.valid)).toBeTruthy();
    }));
  }, 50000);

  /*
  it('jscu: EC/RSA encryption and signing test with ephemeral ECDH keys',  async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.jscuEncryptConfEphemeral(paramObject), sign: param.jscuSignConf(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid), `failed at ${p}`).to.be.true;
      }));
    }));
  }, 50000);
  */
});
