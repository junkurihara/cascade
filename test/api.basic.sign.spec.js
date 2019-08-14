import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params-basic.js';

describe(`${env}: public key signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  });

  it('jscu: EC/RSA signing test',  async function () {
    this.timeout(50000);
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const encryptionKeys = {
          privateKeyPassSets:[ { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' } ] // for Signing
        };
        const encryptConfig = { sign: param.jscuSignConf(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {sign_verify: 'jscu'}, mode: ['sign']}
        );
        const encryptionResult = await cascade.sign({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          publicKeys: [ param.Keys[paramObject.name][idx].publicKey.keyString ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {sign_verify: 'jscu'}, mode: ['verify']}
        );
        const decryptionResult = await cascade.verify({ message, signature: encryptionResult.signature, keys: decryptionKeyImported });
        expect(decryptionResult.every((s) => s.valid), `failed at ${p}`).to.be.a.true;
      }));
    }));
  });

  it('jscu: EC/RSA signing test with multiple secret keys',  async function () {
    this.timeout(50000);
    await Promise.all(param.paramArray.map( async (paramObject) => {
      await Promise.all(paramObject.param.map( async (p, idx) => {
        const subidx = (idx===0) ? idx+1 : 0;
        const encryptionKeys = {
          privateKeyPassSets:[
            { privateKey: param.Keys[paramObject.name][subidx].privateKey.keyString, passphrase: '' },
            { privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: '' }
          ] // for Signing
        };
        const encryptConfig = { sign: param.jscuSignConf(paramObject) };

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {sign_verify: 'jscu'}, mode: ['sign']}
        );
        const encryptionResult = await cascade.sign({ message, keys: encryptionKeyImported, config: encryptConfig});

        const decryptionKeys = {
          publicKeys:[
            // param.Keys[paramObject.name][0].publicKey.keyString,
            param.Keys[paramObject.name][idx].publicKey.keyString,
          ] // for verification
        };
        const decryptionKeyImported = await cascade.importKeys(
          'string', {keys: decryptionKeys, suite: {sign_verify: 'jscu'}, mode: ['verify']}
        );
        const decryptionResult = await cascade.verify({ message, signature: encryptionResult.signature, keys: decryptionKeyImported });
        expect(decryptionResult.every((s) => (s.valid || s.valid === undefined)), `failed at ${p}`).to.be.true;
      }));
    }));
  });

});
