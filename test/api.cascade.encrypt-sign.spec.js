import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params-basic.js';

describe(`${env}: cascaded single public key encryption/decryption with simultaneous signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  });

  it('jscu: EC/RSA encryption and signing mono-step procedure test with ECDH ephemeral keys',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeral(message, param, []);
  });

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via session key encrypt with ECDH ephemeral keys',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('jscu: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt with ECDH ephemeral keys',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });


  it('jscu: EC/RSA encryption and signing hybrid-step procedure test without externalKey entry in the final step',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeralWithoutExternalKeyEntryInFinalStep(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test without externalKey entry in the first step',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeralWithoutExternalKeyEntryInFirstStep(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConfWithoutExternalKey, sign: {required: true} },
    ]);
  });

  it('jscu: EC/RSA encryption and signing mono-step procedure test',  async function () {
    this.timeout(50000);
    await jscuMainRoutine(message, param, []);
  });

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via session key encrypt',  async function () {
    this.timeout(50000);
    await jscuMainRoutine(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('jscu: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt',  async function () {
    this.timeout(50000);
    await jscuMainRoutine(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('openpgp: EC/RSA encryption and signing mono-step procedure test',  async function () {
    this.timeout(50000);
    await openpgpMainRoutine(message, param, []);
  });

  it('openpgp: EC/RSA encryption and signing hybrid-step procedure test via session key encrypt',  async function () {
    this.timeout(50000);
    await openpgpMainRoutine(message, param, [
      { encrypt: param.openpgpOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('openpgp: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt',  async function () {
    this.timeout(50000);
    await openpgpMainRoutine(message, param, [
      { encrypt: param.openpgpOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.openpgpOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  });

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via public key encrypt',  async function () {
    this.timeout(50000);
    await jscuMainRoutine(message, param, [
      { encrypt: param.jscuOnetimePublicEncryptConf, sign: {required: true} },
    ]);
  });

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via public key encrypt with ephemeralKeys',  async function () {
    this.timeout(50000);
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimePublicEncryptConf, sign: {required: true} },
    ]);
  });

  it('openpgp: EC/RSA encryption and signing hybrid-step procedure test via public key encrypt',  async function () {
    this.timeout(50000);
    await openpgpMainRoutine(message, param, [
      { encrypt: param.openpgpOnetimePublicEncryptConf, sign: {required: true} },
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

      const serialized = encrypted.serialize();
      const deserialized = cascade.importCascadedBuffer(serialized);

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

    }));
  }));
}

async function jscuMainRoutineEphemeralWithoutExternalKeyEntryInFinalStep(message, param, precedenceProcedure){
  await Promise.all(param.paramArray.map(async (paramObject) => {
    await Promise.all(paramObject.param.map(async (p, idx) => {

      const encryptionKeys = {
        publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString],
        privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}] // for Signing
      };
      const encryptionProcedure = precedenceProcedure.concat(
        [{encrypt: param.jscuEncryptConfEphemeralNoExternalKey(paramObject), sign: param.jscuSignConf(paramObject)}]
      );

      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['encrypt', 'sign']}
      );

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure}).catch(e => e);
      expect(eProcess.message === 'FinalStepMustBeExternalKey').to.be.true;
    }));
  }));
}

async function jscuMainRoutineEphemeralWithoutExternalKeyEntryInFirstStep(message, param, precedenceProcedure){
  await Promise.all(param.paramArray.map(async (paramObject) => {
    await Promise.all(paramObject.param.map(async (p, idx) => {

      const encryptionKeys = {
        publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString],
        privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}] // for Signing
      };
      const encryptionProcedure = precedenceProcedure.concat(
        [{encrypt: param.jscuEncryptConfEphemeralNoExternalKey(paramObject), sign: param.jscuSignConf(paramObject)}]
      );

      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['encrypt', 'sign']}
      );

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure}).catch(e => e);
      expect(eProcess.message === 'PrecedenceMustBeExternalKey').to.be.true;
    }));
  }));
}

async function jscuMainRoutine(message, param, precedenceProcedure){
  await Promise.all(param.paramArray.map(async (paramObject) => {
    await Promise.all(paramObject.param.map(async (p, idx) => {

      const encryptionKeys = {
        publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString],
        privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}] // for Signing
      };
      const encryptionProcedure = precedenceProcedure.concat(
        [{encrypt: param.jscuEncryptConf(paramObject, idx), sign: param.jscuSignConf(paramObject)}]
      );

      const encryptionKeyImported = await cascade.importKeys(
        'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['encrypt', 'sign']}
      );

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure});
      const encrypted = await eProcess.encrypt(message);

      const serialized = encrypted.serialize();
      const deserialized = cascade.importCascadedBuffer(serialized);

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

      const serialized = encrypted.serialize();
      const deserialized = cascade.importCascadedBuffer(serialized);

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

    }));
  }));
}