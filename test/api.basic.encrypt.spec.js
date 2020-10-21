import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import {createParam} from './params-basic.js';

describe(`${env}: public key encryption/decryption`, () => {

  let message;
  let param;

  beforeAll(async () => {
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  }, 50000);

  it('jscu: EC/RSA encryption test', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ],
        };
        const encryptConfig = { encrypt: param.jscuEncryptConf(paramObject, idx) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu' }, mode: ['encrypt']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu'}, mode: ['decrypt']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.data.toString()===message.toString()).toBeTruthy();
      }));
    }));
  }, 50000);

  it('jscu: EC/RSA encryption test with ephemeral ECDH key', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ],
        };
        const encryptConfig = { encrypt: param.jscuEncryptConfEphemeral(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu' }, mode: ['encrypt']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ],
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu'}, mode: ['decrypt']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.data.toString()===message.toString()).toBeTruthy();
      }));
    }));
  }, 50000);

  it('jscu: EC/RSA encryption test with multiple public keys', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [
            param.Keys[paramObject.name][idx].publicKey.keyString,
            param.Keys[paramObject.name][idx].publicKey.keyString
          ],
        };
        const encryptConfig = { encrypt: param.jscuEncryptConf(paramObject, idx) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu' }, mode: ['encrypt']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[
            { privateKey: param.Keys[paramObject.name][0].privateKey.keyString, passphrase: '' }, // this sometimes failed
            { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' }
          ],
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu'}, mode: ['decrypt']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.data.toString()===message.toString()).toBeTruthy();
      }));
    }));
  }, 50000);

  it('jscu: EC/RSA encryption test with multiple public keys with ephemeral ECDH', async () => {
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [
            param.Keys[paramObject.name][idx].publicKey.keyString,
            param.Keys[paramObject.name][idx].publicKey.keyString
          ],
        };
        const encryptConfig = { encrypt: param.jscuEncryptConfEphemeral(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu' }, mode: ['encrypt']}
        );
        const encryptionResult = await cascade.encrypt({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          privateKeyPassSets:[
            { privateKey: param.Keys[paramObject.name][0].privateKey.keyString, passphrase: '' }, // this sometimes failed
            { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' }
          ],
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu'}, mode: ['decrypt']}
        );
        const decryptionResult = await cascade.decrypt({ data: encryptionResult, keys: decryptionKeyImported });
        expect(decryptionResult.data.toString()===message.toString()).toBeTruthy();
      }));
    }));
  }, 50000);

});
