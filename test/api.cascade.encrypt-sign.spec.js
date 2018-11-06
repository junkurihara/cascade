import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

import {createParam} from './params.basic.js';
import {createEncryptionCascade} from '../src';

describe(`${env}: single public key encryption/decryption with simultaneous signing/verification`, () => {

  let message;
  let param;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  });

  it('jscu: EC/RSA encryption and signing mono-step procedure test', async () => {
    await Promise.all(param.paramArray.map(async (paramObject) => {
      await Promise.all(paramObject.param.map(async (p, idx) => {
        const encryptionKeys = {
          publicKeys: [param.Keys[paramObject.name][idx].publicKey.keyString],
          privateKeyPassSets: [{privateKey: param.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}] // for Signing
        };
        const encryptionProcedure = [
          {encrypt: Object.assign({onetimeKey: {keyParams: {type: 'session', length: 32}}}, param.jscuSessionEncryptConf), sign: {required: true}},
          {encrypt: param.jscuEncryptConf(paramObject, idx), sign: param.jscuSignConf(paramObject)}
        ];

        const encryptionKeyImported = await cascade.importKeys(
          'string', {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu' }, mode: ['encrypt', 'sign']}
        );

        const process = await createEncryptionCascade({keys: encryptionKeyImported, procedure: encryptionProcedure});
        // console.log(process);

      }));
    }));
  });
});