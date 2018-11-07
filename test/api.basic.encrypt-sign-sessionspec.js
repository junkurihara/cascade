import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params-basic.js';

describe(`${env}: session key encryption/decryption with simultaneous signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  });

  it('jscu: symmetric key encryption and public key signing test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          sessionKey: param.Keys.sessionKey,
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.jscuSessionEncryptConf, sign: param.jscuSignConf(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          sessionKey: param.Keys.sessionKey,
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });
  
  it('openpgp: symmetric key encryption and public key signing test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          sessionKey: param.Keys.sessionKey,
          privateKeyPassSets:[ { privateKey:param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.openpgpgSessionEncryptConf, sign: param.openpgpSignConf };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          sessionKey: param.Keys.sessionKey,
          publicKeys: [param.KeysGPG[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });


});