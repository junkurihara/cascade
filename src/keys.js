/**
 * keys.js
 */

import {Jscu} from './suite_jscu.js';
import {OpenPGP} from './suite_openpgp.js';

export class Keys {
  async from(format, {keys, suite, mode}){

    if(mode.indexOf('encrypt') >= 0) {
      if(mode.indexOf('verify') >= 0 || mode.indexOf('decrypt') >= 0) throw new Error('InvalidMode');
      if (typeof keys.publicKeys !== 'undefined'){
        if (typeof keys.sessionKey !== 'undefined') throw new Error('SessionKeyAndPublicKeyAreExclusive');
      } else {
        if (typeof keys.sessionKey === 'undefined') throw new Error('NoSessionKeyOrPublicKeyIsGiven');
      }
    }

    if(mode.indexOf('decrypt') >= 0) {
      if(mode.indexOf('sign') >= 0 || mode.indexOf('encrypt') >= 0) throw new Error('InvalidMode');
      if (typeof keys.privateKeyPassSets !== 'undefined'){
        if (typeof keys.sessionKey !== 'undefined') throw new Error('SessionKeyAndPrivateKeyAreExclusive');
      } else {
        if (typeof keys.sessionKey === 'undefined') throw new Error('NoSessionKeyOrPrivateKeyIsGiven');
      }
    }

    if(mode.indexOf('sign') >= 0){
      if(mode.indexOf('verify') >= 0 || mode.indexOf('decrypt') >= 0) throw new Error('InvalidMode');
      if(typeof keys.privateKeyPassSets === 'undefined') throw new Error('NoPrivateKey');
    }
    if(mode.indexOf('verify') >= 0){
      if(mode.indexOf('sign') >= 0 || mode.indexOf('encrypt') >= 0) throw new Error('InvalidMode');
      if(typeof keys.publicKeys === 'undefined') throw new Error('NoPublicKey');
    }

    let obj;
    if (format === 'string') obj = await importKeyStrings({keys, suite, mode});
    else if (format === 'object') obj = await importKeyObjects({keys, suite, mode});
    else throw new Error('UnsupportedAtThisPoint');

    this._keys = obj.keys;
    this._suite = obj.suite;
    this._mode = obj.mode;

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

/**
 * Functions to import keys and translate them to suite-specific key objects.
 * @param format
 * @param keys
 * @param suite
 * @param mode
 * @return {Promise<Keys>}
 */
export async function importKeys(format='string', {keys, suite, mode}){
  const keyObj = new Keys();
  await keyObj.from(format, {keys, suite, mode});
  return keyObj;
}


/**
 * import from keystring, i.e., pem
 * @param keys
 * @param suite
 * @param mode
 * @return {Promise<{keys, suite: *, mode: *}>}
 */
async function importKeyStrings({keys, suite, mode}){
  const keyObjects = {};

  if (keys.sessionKey) keyObjects.sessionKey = keys.sessionKey; // symmetric key

  const modes = [
    {name: 'encrypt_decrypt', op: {public: 'encrypt', private: 'decrypt'}},
    {name: 'sign_verify', op: {public: 'verify', private: 'sign'}}
  ];
  await Promise.all(modes.map( async (modeOjbect) => {
    if(typeof suite[modeOjbect.name] !== 'undefined') {


      let suiteObj;
      if (suite[modeOjbect.name] === 'jscu') suiteObj = Jscu;
      else if (suite[modeOjbect.name] === 'openpgp') suiteObj = OpenPGP;
      else throw new Error('InvalidSuite');

      if (mode.indexOf(modeOjbect.op.public) >= 0) {
        if (keys.publicKeys) keyObjects.publicKeys = await Promise.all(keys.publicKeys.map( (pk) => suiteObj.importKey('pem', pk)));
      }
      else if (mode.indexOf(modeOjbect.op.private) >= 0) {
        if (keys.privateKeyPassSets) {
          keyObjects.privateKeys = await Promise.all(
            keys.privateKeyPassSets.map((pkps) => suiteObj.importKey('pem', pkps.privateKey, pkps.passphrase))
          );
        }
      }
      else throw new Error('InvalidKeyMode');
    }
  }));

  return { keys: keyObjects, suite, mode };
}

/**
 * just import from key object
 * @param keys
 * @param suite
 * @param mode
 * @return {Promise<{keys, suite: *, mode: *}>}
 */
async function importKeyObjects({keys, suite, mode}){
  const keyObjects = {};

  if (keys.sessionKey) keyObjects.sessionKey = keys.sessionKey; // symmetric key

  if (keys.publicKeys) keyObjects.publicKeys = keys.publicKeys;

  if (keys.privateKeys) keyObjects.privateKeys = keys.privateKeys;

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
    returnKey = await OpenPGP.generateKey({
      userIds: keyParams.userIds,
      passphrase: keyParams.passphrase,
      params: keyParams.keyParams
    })
      .catch((e) => {
        throw new Error(`GPGKeyGenerationFailed: ${e.message}`);
      });

  }
  else if (keyParams.suite === 'jscu') { /** js-crypto-utils **/
    returnKey = await Jscu.generateKey({
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