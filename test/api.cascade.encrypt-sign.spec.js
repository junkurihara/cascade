import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import {createParam} from './params-basic.js';

describe(`${env}: cascaded single public key encryption/decryption with simultaneous signing/verification`, () => {

  let message;
  let param;

  beforeAll(async () => {
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  }, 50000);

  it('jscu: EC/RSA encryption and signing mono-step procedure test with ECDH ephemeral keys',  async () => {
    await jscuMainRoutineEphemeral(message, param, []);
  }, 50000);

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via session key encrypt with ECDH ephemeral keys',  async () => {
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  }, 50000);

  it('jscu: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt with ECDH ephemeral keys',  async () => {
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  }, 50000);


  it('jscu: EC/RSA encryption and signing hybrid-step procedure test without externalKey entry in the final step',  async () => {
    await jscuMainRoutineEphemeralWithoutExternalKeyEntryInFinalStep(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  }, 50000);

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test without externalKey entry in the first step',  async () => {
    await jscuMainRoutineEphemeralWithoutExternalKeyEntryInFirstStep(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConfWithoutExternalKey, sign: {required: true} },
    ]);
  }, 50000);

  it('jscu: EC/RSA encryption and signing mono-step procedure test',  async () => {
    await jscuMainRoutine(message, param, []);
  }, 50000);

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via session key encrypt',  async () => {
    await jscuMainRoutine(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  }, 50000);

  it('jscu: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt',  async () => {
    await jscuMainRoutine(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  }, 50000);

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via public key encrypt',  async () => {
    await jscuMainRoutine(message, param, [
      { encrypt: param.jscuOnetimePublicEncryptConf, sign: {required: true} },
    ]);
  }, 50000);

  it('jscu: EC/RSA encryption and signing hybrid-step procedure test via public key encrypt with ephemeralKeys',  async () => {
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimePublicEncryptConf, sign: {required: true} },
    ]);
  }, 50000);

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
      expect(decrypted[0].data.toString() === message.toString()).toBeTruthy();
      expect(decrypted.every( (obj) => obj.signatures.every( (s) => s.valid))).toBeTruthy();

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

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure}).catch((e) => e);
      expect(eProcess.message === 'FinalStepMustBeExternalKey').toBeTruthy();
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

      const eProcess = await cascade.createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure}).catch((e) => e);
      expect(eProcess.message === 'PrecedenceMustBeExternalKey').toBeTruthy();
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
      expect(decrypted[0].data.toString() === message.toString()).toBeTruthy();
      expect(decrypted.every( (obj) => obj.signatures.every( (s) => s.valid))).toBeTruthy();

    }));
  }));
}
