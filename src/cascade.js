/**
 * cascade.js
 */

import {OpenPGP} from './suite_openpgp.js';
import {Jscu} from './suite_jscu.js';
import {generateKeyObject, importKeys, Keys} from './keys.js';
import {Signature} from './signature.js';
import * as core from './core.js';
import cloneDeep from 'lodash/cloneDeep';


export async function createEncryptionCascade({keys, procedure}){
  const localKeys = cloneDeep(keys);
  const localProcedure = procedure.map( (x) => cloneDeep(x));

  const cascade = new Cascade();
  cascade._init({mode: 'encrypt', keys: localKeys, procedure: localProcedure});
  await cascade._initEncryptionProcedure();

  return cascade;
}

export function createDecryptionCascade({keys, encrypted}){
  const localKeys = cloneDeep(keys);

  const cascade = new Cascade();
  cascade._init({mode: 'decrypt', keys: localKeys, encrypted});
  cascade._initDecryptionProcedure();

  return cascade;
}

////////////////////
const modes = ['encrypt', 'decrypt'];
class Cascade extends Array {
  _init({mode, keys, procedure, encrypted}){
    // assertions
    if (modes.indexOf(mode) < 0) throw new Error('InvalidMode');
    if (!(keys instanceof Keys)) throw new Error('NotKeyObject');
    if (keys.mode.indexOf(mode) < 0) throw new Error('UnmatchedKeyMode');

    this._cascadeMode = mode;
    this._orgKeys = keys;

    if (mode === 'encrypt') {
      if (!(procedure instanceof Array)) throw new Error('NotArrayProcedure');
      const initial = procedure.map( (config) => {
        if(typeof config.encrypt === 'undefined') throw new Error('InvalidProcedure');
        return {config};
      });
      this.push(...initial);
    }

    if (mode === 'decrypt') {
      if (!(encrypted instanceof Array)) throw new Error('NotArrayEncryptedData');
      const initial = encrypted.map( (encryptedObject) => {
        if(typeof encryptedObject.message === 'undefined') throw new Error('InvalidEncryptedMessage');
        return {data: encryptedObject};
      });
      this.push(...initial);
    }

    // set original key to the final step in the procedure
    this[this.length - 1].keys = this._orgKeys;
  }

  async _initEncryptionProcedure(){
    // export signingKey for precedence
    const signingKeys = this._orgKeys.keys.privateKeys;

    const precedence = Array.from(this).slice(0, this.length -1);
    await Promise.all(precedence.map( async (proc, idx) => {
      if (typeof proc.config.encrypt.onetimeKey === 'undefined') throw new Error('NoKeyParamsGiven');

      const suiteObject = {encrypt_decrypt: proc.config.encrypt.suite};
      const modeArray = ['encrypt'];

      // key generation for encryption at this step
      const keyParams = Object.assign({ suite: proc.config.encrypt.suite}, proc.config.encrypt.onetimeKey);
      delete proc.config.encrypt.onetimeKey;
      const onetimeKey = await generateKeyObject(keyParams); // generate keys
      const onetimeKeyObject = (keyParams.keyParams.type === 'session')
        ? {sessionKey: onetimeKey.key}
        : {publicKeys: [onetimeKey.publicKey]};

      // message for encryption at next step.
      // [NOTE] message for the first step is directly given message to be encrypted, otherwise, previous private/session keys;
      let nextStepMessage;
      if (keyParams.keyParams.type === 'session') nextStepMessage = onetimeKey.key;
      else {
        if (keyParams.suite === 'jscu') nextStepMessage = await onetimeKey.privateKey.export('der');
        else if (keyParams.suite === 'openpgp') nextStepMessage = onetimeKey.privateKey.toPacketlist().write();
        else throw new Error('UnknownSuite');
      }
      this[idx+1].message = nextStepMessage;

      // updated config and key object for signing and key import
      if (typeof proc.config.sign !== 'undefined' && proc.config.sign.required){
        proc.config.sign = Object.assign(proc.config.sign, this[this.length-1].config.sign);
        onetimeKeyObject.privateKeys = signingKeys;
        suiteObject.sign_verify = proc.config.sign.suite;
        modeArray.push('sign');
      }

      this[idx].keys = await importKeys('object', {keys:onetimeKeyObject, suite: suiteObject, mode: modeArray});
    }));
  }

  _initDecryptionProcedure(){
    // do nothing at this point
  }

  async encrypt(message){
    if(this._cascadeMode !== 'encrypt') throw new Error('NotEncryptionCascade');
    if(!(message instanceof Uint8Array)) throw new Error('NotUint8ArrayMessage');

    // set given message as the first step message
    this[0].message = message;

    return await Promise.all(Array.from(this).map( (proc) => core.encrypt(proc)));
  }

  async decrypt(){
    if(this._cascadeMode !== 'decrypt') throw new Error('NotDecryptionCascade');

    // export verificationKey for precedence
    const verificationKeys = this._orgKeys.keys.publicKeys;

    // serialized decryption
    const decrypted = new Array(this.length);
    for(let idx = this.length-1; idx >= 0; idx--) {
      if (!(this[idx].keys instanceof Keys)) throw new Error('InvalidKeysObject');
      if (typeof this[idx].data === 'undefined') throw new Error('InvalidDataObject');

      decrypted[idx] = await core.decrypt(this[idx]);

      // assign decrypted message as previous step decryption key
      if(idx > 0){
        const suiteObject = {encrypt_decrypt: this[idx-1].data.message.suite};
        const modeArray = ['decrypt'];

        let nextDecryptionKeyObject;
        if (this[idx-1].data.message.keyType === 'session_key_encrypt') nextDecryptionKeyObject = {sessionKey: decrypted[idx].data};
        else {
          if (this[idx-1].data.message.suite === 'jscu'){
            nextDecryptionKeyObject = {privateKeys: [await Jscu.importKey('der', decrypted[idx].data)]};
          }
          else if (this[idx-1].data.message.suite === 'openpgp'){
            nextDecryptionKeyObject = {privateKeys: [await OpenPGP.importKey('der', decrypted[idx].data)]};
          }
          else throw new Error('UnknownSuite');
        }

        // updated config and key object for signing and key import
        if (this[idx-1].data.signature instanceof Signature && typeof verificationKeys !== 'undefined'){
          nextDecryptionKeyObject.publicKeys = verificationKeys;
          suiteObject.sign_verify = this[idx-1].data.signature.suite;
          modeArray.push('verify');
        }
        // WA for embedded signature
        else if (typeof this[idx-1].data.message !== 'undefined'
          && this[idx-1].data.message.suite === 'openpgp'
          && typeof verificationKeys !== 'undefined' ) {
          nextDecryptionKeyObject.publicKeys = verificationKeys;
          suiteObject.sign_verify = 'openpgp';
          modeArray.push('verify');
        }

        this[idx-1].keys = await importKeys('object', { keys: nextDecryptionKeyObject, suite: suiteObject, mode: modeArray });
      }
    }
    return decrypted;

  }

  get mode () { return this._cascadeMode; }
  get keys () { return this._orgKeys; }
  // get allKeys () { return null; } // TODO
}


