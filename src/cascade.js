/**
 * cascade.js
 */

import {OpenPGP} from './suite_openpgp.js';
import {Jscu} from './suite_jscu.js';
import {generateKeyObject} from './keys.js';
import {importMessage} from './message';
import {importKey} from './obsolete';


export class Cascade {
  ////////////////////
  constructor(){
  }

  ////////////////////
}

/**
 * Decrypt single encrypted object in serialized manner
 * @param encrypted {Object}
 * @param keys {Object}
 * @param nextEncrypted {Object}
 * @return {Promise<{success: boolean, message: *}>}
 */
export const decryptSingle = async ({encrypted, keys, nextEncrypted}) => {
  let decryptedObj;
  if (encrypted.message.suite === 'openpgp') { /** OpenPGP **/
    const options = {}; // api_openpgp.js encrypt API options
    decryptedObj = await OpenPGP.decrypt({encrypted, keys, options});
  }
  else if (encrypted.message.suite === 'jscu') { /** js-crypto-utils **/
    const options = {};
    decryptedObj = await Jscu.decrypt({encrypted, keys, options});
  }
  else throw new Error('UnsupportedCryptoSuite');

  // handling detached sign
  if (encrypted.signature) {
    decryptedObj.signature = await verifySingle({keys, message: decryptedObj.data, signature: encrypted.signature});
  }

  // check validity if signature exists
  let validity = true;
  if (decryptedObj.signature) validity = decryptedObj.signature.every((elem) => elem.valid === true);


  if (nextEncrypted) { // still have next proc, so need to import key
    // importing keys as desired format
    let keyObject;
    if (nextEncrypted.message.suite === 'openpgp') { /** OpenPGP **/
      if (nextEncrypted.message.keyType === 'public_key_encrypt') {
        keyObject = {privateKeyPassSets: [{privateKey: decryptedObj.data, passphrase: ''}]};
      } else if (nextEncrypted.message.keyType === 'session_key_encrypt') {
        keyObject = {sessionKey: {key: decryptedObj.data, algorithm: nextEncrypted.message.options.algorithm}};
      }
    }
    else if(nextEncrypted.message.suite === 'jscu') { /** js-crypto-utils **/
      if (nextEncrypted.message.keyType === 'public_key_encrypt') {
        throw new Error('public_key_encrypt using jscu is not supported'); // TODO
      } else if (nextEncrypted.message.keyType === 'session_key_encrypt') {
        keyObject = {sessionKey: {key: decryptedObj.data, algorithm: nextEncrypted.message.options.algorithm}};
      }
    }
    else throw new Error('UnsupportedCryptoSuite');

    return {success: validity, message: keyObject};
  }
  else return {success: validity, message: decryptedObj};
};

/**
 * Generate one time keys for hybrid+ encryption. Unlike generateKey API, this directly outputs non-formatted objects.
 * @param keyParams
 * @return {Promise<{keys: ({publicKeys: *[]}|{sessionKey: {data: *, algorithm: *}}), keyAsNewMsg: {message: *, filename: null}}>}
 */
export async function generateOneTimeKey(keyParams) {
  console.debug('generate onetime key');

  const keyObj = await generateKeyObject(keyParams);

  // formatting
  let newKey;
  let keyAsNewMsg;
  if (keyParams.keyParams.type === 'SYMMETRIC') {
    newKey = {sessionKey: {key: keyObj.key, algorithm: keyParams.keyParams.algorithm}};
    keyAsNewMsg = importMessage(keyObj.key);
  }
  else {
    if (keyParams.suite === 'openpgp') {
      /** OpenPGP **/
      newKey = {publicKeys: [keyObj.publicKey]};
      keyAsNewMsg = importMessage(keyObj.privateKey.toPacketlist().write());
    }
    else if (keyParams.suite === 'jscu') {
      /** js-crypto-utils **/
      newKey = {publicKeys: [keyObj.publicKey]};
      keyAsNewMsg = importMessage(await keyObj.privateKey.export('der'));
    }
    else throw new Error('UnsupportedCryptoSuite');
  }

  return {keys: newKey, keyAsNewMsg};
}

/**
 * Do encryption at every stage in parallel
 * @param message
 * @param keys
 * @param procedure
 * @return {Promise<[* , any]>}
 */
export const encryptParallel = async ({message, originalKeyString, procedure}) => {
  console.debug('do parallel key generation and encryption');

  // invoke key generation process here for 1st to last 2 procedure
  const generatedKeys = await Promise.all(procedure.slice(0, -1).map((proc) => generateOneTimeKey(proc.encrypt))); // TODO: ここもImportKeyすればいいのか

  // import original keys and create key sequence
  const origKey = await importKey(originalKeyString, procedure.slice(-1)[0], 'encrypt');
  const newKeys = [{
    keys: origKey, keyAsNewMsg: importMessage(message) // key as new message
  }];
  for (let i = 1; i < generatedKeys.length + 1; i++) newKeys[i] = generatedKeys[i - 1];

  // sorting so as to match public key to corresponding message to be encrypted
  let sortedMsgKeyArray = newKeys.map((val, idx, arr) => ({
    procedure: procedure[idx],
    message: val.keyAsNewMsg,
    keys: arr[(arr.length + idx + 1) % arr.length].keys
  }));

  if (origKey.privateKeys) {
    sortedMsgKeyArray = await Promise.all(sortedMsgKeyArray.map(async (msgKey, idx) => {
      const returnKeys = Object.assign({}, msgKey);
      if (procedure[idx].sign) {
        if (!procedure[idx].sign.required) { // if required, consider signing in encryption
          console.debug(`sign is not required for proc ${idx}`);
          if (msgKey.keys.privateKeys) delete returnKeys.keys.privateKeys;
        }
        else if (procedure[idx].encrypt.suite === 'openpgp' && procedure.slice(-1)[0].sign.suite === 'openpgp') {
          // when the encryption and signing suites are not both openpgp, signature will be able to attached simultaneously with encryption.
          console.debug(`sign will be embedded for proc ${idx} in openpgp (but may be detached due to external options)`);
          returnKeys.keys.privateKeys = origKey.privateKeys; // the signature will be given with original private key
        }
        else { // detached sign generation is invoked
          console.debug(`sign separately for proc ${idx}`);
          returnKeys.message.signature = (await signSingle({
            procedure: procedure.slice(-1)[0],
            keys: origKey,
            message: msgKey.message,
            output: procedure[idx].sign.output
          })).signature;
          if (msgKey.keys.privateKeys) delete returnKeys.keys.privateKeys;
        }
      } else {
        if (msgKey.keys.privateKeys) delete returnKeys.keys.privateKeys;
      }

      return returnKeys;
    }));
  }

  // invoke encryption process here for 1st to last procedure
  return Promise.all(sortedMsgKeyArray.map((x) => encryptSingle(x)));
};

/**
 * Encrypt single object
 * @param procedure
 * @param message {Object}
 * @param keys
 * @return {Promise<*>}
 */
const encryptSingle = async ({procedure, message, keys}) => {
  const output = Object.assign(
    {encrypt: procedure.encrypt.output},
    (typeof procedure.sign !== 'undefined') ? {sign: procedure.sign.output} : {}
  );

  let encryptedObj;
  if (procedure.encrypt.suite ==='openpgp') { /** OpenPGP **/
    const options = procedure.encrypt.options;
    encryptedObj = await OpenPGP.encrypt({message, keys, options, output});
  }
  else if (procedure.encrypt.suite === 'jscu') { /** js-crypto-utils **/
    const options = procedure.encrypt.options;
    encryptedObj = await Jscu.encrypt({message, keys, options, output});
  }
  else throw new Error('UnsupportedCryptoSuite');

  // handling detachedSign (e.g., openpgp encryption with options.detached = true)
  if (message.signature) encryptedObj.signature = message.signature;

  return encryptedObj;
};


/**
 *
 * @param keyMsg
 * @return {Promise<any>}
 */
const signSingle = async ({procedure, message, keys, output}) => {
  if (typeof output === 'undefined') throw new Error('OutputFormatRequired');

  let signature;
  if (procedure.sign.suite === 'openpgp') { /** OpenPGP **/
    const options = procedure.sign.options; // api_openpgp.js encrypt API options
    options.armor = false;
    options.detached = true; // default values
    signature = await OpenPGP.sign({
      message, keys,
      options,
      output: {sign: output}
    });
  }
  else if (procedure.sign.suite === 'jscu') { /** Naiive suite using jscu **/
    signature = await Jscu.sign({
      message, keys,
      options: procedure.sign.options,
      output: {sign: output}
    });
  }
  else throw new Error('UnsupportedCryptoSuite');

  return signature;

};


/**
 *
 * @param keys
 * @param message
 * @param signature
 * @return {Promise<*>}
 */
const verifySingle = async ({keys, message, signature}) => {
  const output = {sign: signature.messageType};

  let verifiedSig;
  if (signature.suite === 'openpgp') { /** OpenPGP **/
    verifiedSig = await OpenPGP.verify({
      message: importMessage(message), signature,
      keys, options: {}, output
    });
  }
  else if (signature.suite === 'jscu') { /** js-crypto-utils **/
    verifiedSig = await Jscu.verify({
      message: importMessage(message), signature, keys, options: {}, output
    });
  }
  else throw new Error('UnsupportedCryptoSuite');

  return verifiedSig;
};

