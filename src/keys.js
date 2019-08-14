/**
 * keys.js
 */

import cloneDeep from 'lodash.clonedeep';//'lodash/cloneDeep';
import {Jscu} from './suite_jscu.js';

export class Keys {
  async from(format, {keys, suite, mode}){
    // assertion
    if((mode.indexOf('encrypt') >= 0 && mode.indexOf('verify') >= 0)
      || (mode.indexOf('encrypt') >= 0 && mode.indexOf('decrypt') >= 0)
      || (mode.indexOf('decrypt') >= 0 && mode.indexOf('sign') >= 0)
      || (mode.indexOf('sign') >= 0 && mode.indexOf('verify') >= 0)
    ) throw new Error('InvalidMode');

    if(mode.indexOf('encrypt') >= 0) {
      if (typeof keys.publicKeys !== 'undefined'){
        if (typeof keys.sessionKey !== 'undefined') throw new Error('SessionKeyAndPublicKeyAreExclusive');
      } else {
        if (typeof keys.sessionKey === 'undefined') throw new Error('NoSessionKeyOrPublicKeyIsGiven');
      }
    }

    if(mode.indexOf('decrypt') >= 0) {
      if (typeof keys.privateKeyPassSets !== 'undefined' || typeof keys.privateKeys !== 'undefined'){
        if (typeof keys.sessionKey !== 'undefined') throw new Error('SessionKeyAndPrivateKeyAreExclusive');
      } else {
        if (typeof keys.sessionKey === 'undefined') throw new Error('NoSessionKeyOrPrivateKeyIsGiven');
      }
    }

    if(mode.indexOf('sign') >= 0 && typeof keys.privateKeyPassSets === 'undefined' &&  typeof keys.privateKeys === 'undefined'){
      throw new Error('NoPrivateKey');
    }
    if(mode.indexOf('verify') >= 0 && typeof keys.publicKeys === 'undefined'){
      throw new Error('NoPublicKey');
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
export const importKeys = async (format='string', {keys, suite, mode}) => {
  const localFormat = cloneDeep(format);
  const localKeys = cloneDeep(keys);
  const localSuite = cloneDeep(suite);
  const localMode = cloneDeep(mode);

  const keyObj = new Keys();
  await keyObj.from(localFormat, {keys: localKeys, suite: localSuite, mode: localMode});
  return keyObj;
};


/**
 * import from keystring, i.e., pem
 * @param keys
 * @param suite
 * @param mode
 * @return {Promise<{keys, suite: *, mode: *}>}
 */
const importKeyStrings = async ({keys, suite, mode}) => {
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
};

/**
 * just import from key object
 * @param keys
 * @param suite
 * @param mode
 * @return {Promise<{keys, suite: *, mode: *}>}
 */
const importKeyObjects = async ({keys, suite, mode}) => {
  const keyObjects = {};

  if (keys.sessionKey) keyObjects.sessionKey = keys.sessionKey; // symmetric key

  if (keys.publicKeys) keyObjects.publicKeys = keys.publicKeys;

  if (keys.privateKeys) keyObjects.privateKeys = keys.privateKeys;

  return {keys: keyObjects, suite, mode};
};


/**
 * Basic key generator via jscu APIs. Returns raw objects of keys in both environments from the spec with some additional args.
 * @param keyParams
 * @return {Promise<*>}
 */
export const generateKeyObject = async (keyParams) => {
  const localKeyParams = cloneDeep(keyParams);
  let returnKey;
  if (localKeyParams.suite === 'jscu') { /** js-crypto-utils **/
    returnKey = await Jscu.generateKey({
      passphrase: localKeyParams.passphrase,
      params: localKeyParams.keyParams,
      encryptOptions: localKeyParams.encryptOptions
    })
      .catch((e) => {
        throw new Error(`JscuKeyGenerationFailed: ${e.message}`);
      });
  }
  else throw new Error('UnsupportedCryptoSuite');

  return returnKey;
};
