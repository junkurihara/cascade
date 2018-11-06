import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params.basic.js';

describe(`${env}: single public key encryption/decryption with simultaneous signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  });

  it('jscu: EC/RSA encryption and signing test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.jscuEncryptConf(paramObject, idx), sign: param.jscuSignConf(paramObject) };

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
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });
  
  it('openpgp: RSA/EC encryption and signing test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [param.KeysGPG[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey:param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.openpgpEncryptConf, sign: param.openpgpSignConf };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey:param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
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


  it('mix1 (encrypt: openpgp, sign: jscu): RSA/EC encryption and signing test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [param.KeysGPG[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey:param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.openpgpEncryptConf, sign: param.jscuSignConf(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey:param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
          publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });


  it('mix2 (encrypt: jscu, sign: openpgp): RSA/EC encryption and sining test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString ],
          privateKeyPassSets:[ { privateKey:param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { encrypt: param.jscuEncryptConf(paramObject, idx), sign: param.openpgpSignConf };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'openpgp'}, mode: ['encrypt', 'sign']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey:param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
          publicKeys: [param.KeysGPG[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'openpgp'}, mode: ['decrypt', 'verify']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.signatures.every((s) => s.valid)).to.be.true;
      }));
    }));
  });


  // TODO: symmetric (with and without sign)
  // TODO: only encrypt
  // TODO: onnly sign

});