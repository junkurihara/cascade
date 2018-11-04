/**
 * keys.js
 */

import * as openpgp from './api_openpgp.js';
import * as jscu from './api_jscu.js';

/**
 * Import keys as objects
 * @param keys
 * @param proc
 * @param mode
 * @return {Promise<void>}
 */
export const importKey = async function (keys, proc, mode) {
  const keyArrObj = {};
  ///////////////////////////////////////////////
  // For encryption and decryption
  if (proc.encrypt) {
    switch (proc.encrypt.suite) {
    case 'openpgp': {
      /** OpenPGP **/
      if (keys.publicKeys && mode === 'encrypt')
        keyArrObj.publicKeys = await Promise.all( keys.publicKeys.map( (pk) => openpgp.importKey('pem', pk)) );
      if (keys.sessionKey) keyArrObj.sessionKey = keys.sessionKey; // symmetric key
      if (keys.privateKeyPassSets && mode === 'decrypt')
        keyArrObj.privateKeys = await Promise.all(keys.privateKeyPassSets.map( async (pkps) => {
          if(pkps.privateKey instanceof Uint8Array) return openpgp.importKey('der', pkps.privateKey, pkps.passphrase);
          else return openpgp.importKey('pem', pkps.privateKey, pkps.passphrase);
        })); //await readPrivateOpenPGP(keys.privateKeyPassSets); // privateKey
      break;
    }
    case 'jscu': {
      if (keys.sessionKey) keyArrObj.sessionKey = keys.sessionKey; // symmetric key
      break;
    }
    default:
      throw new Error('invalid specification of proc');
    }
  }

  ///////////////////////////////////////////////
  // For signing and verification
  if (proc.sign) {
    switch (proc.sign.suite) {
    case 'openpgp': {
      /** OpenPGP **/
      if (keys.privateKeyPassSets && mode === 'encrypt')
        keyArrObj.privateKeys = await Promise.all(keys.privateKeyPassSets.map( async (pkps) => {
          if(pkps.privateKey instanceof Uint8Array) return openpgp.importKey('der', pkps.privateKey, pkps.passphrase);
          else return openpgp.importKey('pem', pkps.privateKey, pkps.passphrase);
        })); //await readPrivateOpenPGP(keys.privateKeyPassSets); // privateKey
      if (keys.publicKeys && mode === 'decrypt')
        keyArrObj.publicKeys = await Promise.all( keys.publicKeys.map( (pk) => openpgp.importKey('pem', pk)) );
      break;
    }
    case 'jscu': {
      /** js-crypto-utils **/
      if (keys.privateKeyPassSets && mode === 'encrypt') keyArrObj.privateKeys =
        await Promise.all(
          keys.privateKeyPassSets.map( (pkps) => jscu.importKey('pem', pkps.privateKey, pkps.passphrase))
        );
      if (keys.publicKeys && mode === 'decrypt') keyArrObj.publicKeys =
        await Promise.all(
          keys.publicKeys.map( (pk) => jscu.importKey('pem', pk))
        );
      //await readPublicJscu(keys.publicKeys); // my public key for verification
      break;
    }
    default:
      if (proc.sign.required) throw new Error('invalid specification of proc');
    }
  }

  return keyArrObj;
};









//////////////////////////////// TODO: 20181031 below
class Keys {
  async from(format, {keys, suite, mode}){
    let obj;
    if (format === 'string') obj = await importKeyStrings({keys, suite, mode});
    else if (format === 'object') obj = await importKeyObjects({keys, suite, mode});
    else throw new Error('UnsupportedAtThisPoint');

    this._keys = obj.keys;
    this._suite = obj.suite;
    this._mode = obj.mode;

    if(mode.indexOf('encrypt') >= 0) {
      if (typeof this.keys.publicKeys !== 'undefined'){
        if (typeof this.keys.sessionKey !== 'undefined') throw new Error('SessionKeyAndPublicKeyAreExclusive');
      } else {
        if (typeof this.keys.sessionKey === 'undefined') throw new Error('NoSessionKeyOrPublicKeyIsGiven');
      }
    }

    if(mode.indexOf('decrypt') >= 0) {
      if (typeof this.keys.privateKeys !== 'undefined'){
        if (typeof this.keys.sessionKey !== 'undefined') throw new Error('SessionKeyAndPrivateKeyAreExclusive');
      } else {
        if (typeof this.keys.sessionKey === 'undefined') throw new Error('NoSessionKeyOrPrivateKeyIsGiven');
      }
    }

    if(mode.indexOf('sign') >= 0 && typeof this.keys.privateKeys === 'undefined') throw new Error('NoPrivateKey');
    if(mode.indexOf('verify') >= 0 && typeof this.keys.publicKeys === 'undefined') throw new Error('NoPublicKey');

    return true;
  }

  get keys () { return this._keys; }
  get suite () { return this._suite; }
  get mode () { return this._mode; }

  canEncrypt() { return this.mode.indexOf('encrypt') >= 0; }
  canDecrypt() { return this.mode.indexOf('decrypt') >= 0; }
  canSign() { return this.mode.indexOf('sign') >= 0; }
  canVerify() { return this.mode.indexOf('verify') >= 0; }

}

export async function importKeys(format='string', {keys, suite, mode}){
  const keyObj = new Keys();
  await keyObj.from(format, {keys, suite, mode});
  return keyObj;
}

async function importKeyStrings({keys, suite, mode}){
  const keyObjects = {};

  if (keys.sessionKey) keyObjects.sessionKey = keys.sessionKey; // symmetric key

  if (suite.encrypt_decrypt) {
    let suiteObj;
    if(suite.encrypt_decrypt === 'jscu') suiteObj = jscu;
    else if (suite.encrypt_decrypt === 'openpgp') suiteObj = openpgp;
    else throw new Error('InvalidPublicKeyType');

    if (keys.publicKeys) keyObjects.publicKeys = await Promise.all(keys.publicKeys.map( (pk) => suiteObj.importKey('pem', pk)));
  }

  if(suite.sign_verify) {
    let suiteObj;
    if(suite.sign_verify === 'jscu') suiteObj = jscu;
    else if (suite.sign_verify === 'openpgp') suiteObj = openpgp;
    else throw new Error('InvalidConfigForKeyImport');

    if (keys.privateKeyPassSets) {
      keyObjects.privateKeys = await Promise.all(
        keys.privateKeyPassSets.map((pkps) => suiteObj.importKey('pem', pkps.privateKey, pkps.passphrase))
      );
    }
  }

  return { keys: keyObjects, suite, mode };
}

async function importKeyObjects({keys, suite, mode}){
  const keyObjects = {};

  if (keys.sessionKey) keyObjects.sessionKey = keys.sessionKey; // symmetric key

  if (keys.publicKeys) keyObjects.publicKeys = keys.publicKeys;

  if (keys.privateKeyPassSets) {
    keyObjects.privateKeys = keys.privateKeys.map( (pk) => {
      if(pk.isEncrypted) throw new Error('SigningPrivateKeyIsNotDecrypted');
      return pk;
    });
  }

  return {keys: keyObjects, suite, mode};
}


/**
 * Basic key generator via openpgp/jscu APIs. Returns raw objects of keys in both environments from the spec with some additional args.
 * @param keyParams
 * @return {Promise<*>}
 */
export async function generateKeyObject(keyParams) {
  let returnKey;
  if (keyParams.suite === 'openpgp') { /** OpenPGP **/
    returnKey = await openpgp.generateKey({
      userIds: keyParams.userIds,
      passphrase: keyParams.passphrase,
      params: keyParams.keyParams
    })
      .catch((e) => {
        throw new Error(`GPGKeyGenerationFailed: ${e.message}`);
      });
  }
  else if (keyParams.suite === 'jscu') { /** js-crypto-utils **/
    returnKey = await jscu.generateKey({
      passphrase: keyParams.passphrase,
      params: keyParams.keyParams,
      encryptOptions: keyParams.encryptOptions
    })
      .catch((e) => {
        throw new Error(`JscuKeyGenerationFailed: ${e.message}`);
      });
  }
  else throw new Error('UnsupportedCryptoSuite');

  return returnKey;
}