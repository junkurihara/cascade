import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import {createParam} from './params-basic.js';

describe(`${env}: cascaded single public key encryption/decryption with encrypted data pop and simultaneous signing/verification`, () => {

  let message;
  let param;

  beforeAll(async () => {
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;

    param = await createParam();
  }, 100000);

  it('jscu: EC/RSA encryption and signing tribrid-step procedure test via session key encrypt with ECDH ephemeral keys',  async () => {
    await jscuMainRoutineEphemeral(message, param, [
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
      { encrypt: param.jscuOnetimeSessionEncryptConf, sign: {required: true} },
    ]);
  }, 100000);

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
        expect(encrypted[n].message.message.length === 0).toBeTruthy();

        const serialized = encrypted.serialize();
        const serializedExtracted = extracted.map( (obj) => obj.serialize() );

        const deserialized = cascade.importCascadedBuffer(serialized);
        const deserializedExtracted = cascade.importRawEncryptedBufferList(serializedExtracted);
        encrypted.insert(n, extracted); // recover original encrypted message for next loop

        deserialized.insert(n, deserializedExtracted);
        expect(deserialized[n].message.message.length === extracted.length).toBeTruthy();
        expect(deserializedExtracted.length === extracted.length).toBeTruthy();

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
      }

    }));
  }));
}
