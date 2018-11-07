import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params-basic.js';

describe(`${env}: single public key encryption/decryption with simultaneous signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
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


});

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

      const decryptionKeys = {
        privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}],
        publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString], // for Signing
      };
      const decryptionKeyImported = await cascade.importKeys(
        'string', {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['decrypt', 'verify']}
      );

      const dProcess = await cascade.createDecryptionCascade({keys: decryptionKeyImported, encrypted});
      const decrypted = await dProcess.decrypt();
      expect(decrypted[0].data.toString() === message.toString()).to.be.true;
      expect(decrypted.every( (obj) => obj.signatures.every( (s) => s.valid))).to.be.true;

    }));
  }));
}