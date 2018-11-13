import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params-basic.js';

describe(`${env}: cascaded single public key encryption/decryption with encrypted data pop and simultaneous signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  });

  it('jscu: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt with ECDH ephemeral keys',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('openpgp: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt',  async function () {
    this.timeout(50000);
    await openpgpMainRoutine(message, param, [
      { encrypt: param.openpgpOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.openpgpOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });



});

async function jscuMainRoutineEphemeral(message, param, precedenceProcedure){
  await Promise.all(param.paramArray.map(async (paramObject) => {
    await Promise.all(paramObject.param.map(async (p, idx) => {

      const encryptionKeys = {
        publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString],
        privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}] // for Signing
      };
      const encryptionProcedure = precedenceProcedure.concat(
        [{encrypt: param.jscuEncryptConfEphemeral(paramObject), sign: param.jscuSignConf(paramObject)}]
      );

      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['encrypt', 'sign']}
      );

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure});
      const encrypted = await eProcess.encrypt(message);

      for(let n = 0; n < encrypted.length; n++) {
        const extracted = encrypted.extract(n);
        expect(encrypted[n].message.message.length === 0).to.be.true;

        const serialized = encrypted.serialize();
        const deserialized = cascade.importCascadedBuffer(serialized);
        encrypted.insert(n, extracted); // recover original encrypted message for next loop

        deserialized.insert(n, extracted);
        expect(deserialized[n].message.message.length === extracted.length).to.be.true;

        const decryptionKeys = {
          privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}],
          publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString], // for Signing
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['decrypt', 'verify']}
        );

        const dProcess = await cascade.createDecryptionCascade({keys: decryptionKeyImported, encrypted: deserialized});
        const decrypted = await dProcess.decrypt();
        expect(decrypted[0].data.toString() === message.toString(), `failed at ${p}`).to.be.true;
        expect(decrypted.every( (obj) => obj.signatures.every( (s) => s.valid)), `failed at ${p}`).to.be.true;
      }

    }));
  }));
}


async function openpgpMainRoutine(message, param, precedenceProcedure){
  await Promise.all(param.paramArray.map(async (paramObject) => {
    await Promise.all(paramObject.param.map(async (p, idx) => {

      const encryptionKeys = {
        publicKeys: [param.KeysGPG[paramObject.name][idx].publicKey.keyString],
        privateKeyPassSets: [{privateKey: param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: ''}] // for Signing
      };
      const encryptionProcedure = precedenceProcedure.concat(
        [{encrypt: param.openpgpEncryptConf, sign: param.openpgpSignConf}]
      );

      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp' }, mode: ['encrypt', 'sign']}
      );

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure});
      const encrypted = await eProcess.encrypt(message);

      for(let n = 0; n < encrypted.length; n++) {
        const extracted = encrypted.extract(n);
        expect(encrypted[n].message.message.length === 0).to.be.true;

        const serialized = encrypted.serialize();
        const deserialized = cascade.importCascadedBuffer(serialized);
        encrypted.insert(n, extracted); // recover original encrypted message for next loop

        deserialized.insert(n, extracted);
        expect(deserialized[n].message.message.length === extracted.length).to.be.true;


        const decryptionKeys = {
          privateKeyPassSets: [{privateKey: param.KeysGPG[paramObject.name][idx].privateKey.keyString, passphrase: ''}],
          publicKeys: [param.KeysGPG[paramObject.name][idx].publicKey.keyString], // for Signing
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'openpgp', sign_verify: 'openpgp' }, mode: ['decrypt', 'verify']}
        );

        const dProcess = await cascade.createDecryptionCascade({keys: decryptionKeyImported, encrypted: deserialized});
        const decrypted = await dProcess.decrypt();
        expect(decrypted[0].data.toString() === message.toString(), `failed at ${p}`).to.be.true;
        expect(decrypted.every( (obj) => obj.signatures.every( (s) => s.valid)), `failed at ${p}`).to.be.true;
      }

    }));
  }));
}
