/**
 * core.js
 */

import params from './params.js';
import {decryptSingle, encryptParallel} from './cascade.js';
import {importKey, generateKeyObject} from './keys.js';
import {importMessage} from './message.js';
import * as jscu from './api_jscu.js';
import * as openpgp from './api_openpgp.js';

/**
 * Decrypt encrypted array object with given keys.
 * @param encryptedArray {Array}
 * @param keys {Object}
 * @return {Promise<*>}
 */
export async function decryptSeq({encryptedArray, keys}){
  // TODO: AssertionとDefaultParamsの処理、try+catchとメイン関数だけ残す形にする。
  // default params
  console.debug('invoke decryption');

  // import original keys
  const getImportedKeys = async (keyObj, encrypted) => {
    // specs
    const originalSpec = { encrypt: {suite: encrypted.message.suite } };
    if(encrypted.signature && keyObj.publicKeys) originalSpec.sign = {suite: encrypted.signature.suite}; // detached signature
    else if(keyObj.publicKeys) originalSpec.sign = {suite: encrypted.message.suite}; // embedded signature
    // key import as suite-specific key object
    return importKey(keyObj, originalSpec, 'decrypt');
  };


  // serialized decryption
  // TODO: This should be xbrid.decryptSerial in cascade.js
  const originalKeys = await getImportedKeys(keys, encryptedArray[encryptedArray.length-1]);
  let decrypted;
  let currentKeys = originalKeys;
  let validity = true;
  try {
    for (let idx = encryptedArray.length - 1; idx >= 0; idx--) {
      // decryption
      decrypted = await decryptSingle({
        encrypted: encryptedArray[idx],
        keys: currentKeys,
        nextEncrypted: (idx > 0) ? encryptedArray[idx - 1] : null
      });

      // check validity
      if (!decrypted.success) validity = false;

      // the decrypted data is still key, then the returned decrypted object is still key
      if (idx > 0) {
        const imported = await getImportedKeys(decrypted.message, encryptedArray[idx - 1]); // this could be private key or session key, etc.
        currentKeys = (originalKeys.publicKeys) ? Object.assign(imported, {publicKeys: originalKeys.publicKeys}) : imported;
      }
    }
    return Object.assign({success: validity, status: (validity) ? 'OK': 'ValidationFailure'}, decrypted.message);
  }
  catch (e) {
    console.error(e);
    return {success: false, status: `DecryptionFailed: ${e.message}`};
  }
}

/**
 * Encrypt message with the specified procedure. This is just an exposed API of xbrid.encryptParallel.
 * @param message
 * @param keys
 * @param procedureConfig
 * @return {Promise<*>}
 */
export async function encryptSeq({message, keys, procedureConfig}){
  console.debug('invoke encryption');
  // assertion
  if(!Array.isArray(procedureConfig)) throw new Error('NonArrayProcedure');
  if(!procedureConfig.length)throw new Error('EmptyProcedure');

  // default params
  if(!procedureConfig) procedureConfig = params.defaultProcedure;

  // do encryption from first entry to last entry.
  try {
    const encrypted = await encryptParallel({
      message,
      originalKeyString: keys,
      procedure: procedureConfig,
    });

    // Formatting is as below
    // [{message: { message, suite, keyType, keyIds [ {id, type} ]}, signature: {signature, suite, keyIds[{id, type}] }}]
    return {success: true, status: 'OK', data: encrypted};
  }
  catch (e) {
    console.error(e);
    return {success: false, status: `EncryptionFailed: ${e.message}`};
  }
}

//////////////////////////////// TODO: 20181031 below
/**
 * Generate key (pair). This API must be called externally.
 * @param keyParams {object}: a parameter to generate keys in the form of like
 * OpenPGP:
 * { suite: 'openpgp',
 *   userIds,
 *   passphrase: 'omg',
 *   keyParams: { type: 'ECC', keyExpirationTime: 0, curve: 'P-256' } }
 * Simple Crypto Suite using WebCryptoAPI/OpenSSL:
 * { suite: 'jscu',
 *   passphrase: 'omg',
 *   keyParams: {type: 'ECC', curve} } }
 * @return {Promise<*>}
 */
export async function generateKey (keyParams) {
  const keyObj = await generateKeyObject(keyParams);

  // formatting
  if (keyParams.keyParams.type === 'SYMMETRIC') {
    return keyObj;
  }
  else {
    if(keyParams.suite === 'openpgp') { /** OpenPGP **/
      return {
        publicKey: { keyString: keyObj.publicKey.armor(), keyIds: keyObj.keyIds },
        privateKey: Object.assign(
          { keyString: keyObj.privateKey.armor(), keyIds: keyObj.keyIds },
          (keyParams.passphrase) ? {passphrase: keyParams.passphrase} : {})
      };
    }
    else if (keyParams.suite === 'jscu') { /** js-crypto-utils **/
      return {
        publicKey: {
          keyString: await keyObj.publicKey.export('pem', {outputPublic: true}),
          keyIds: keyObj.keyIds
        },
        privateKey: Object.assign(
          { keyString: await keyObj.privateKey.export('pem'), keyIds: keyObj.keyIds },
          (keyParams.passphrase) ? {passphrase: keyParams.passphrase} : {} )
      };
    }
    else throw new Error('InvalidCryptoSuite');
  }
}

/**
 * Basic encryption API that enables signing simultaneously with encrypting message.
 * @param message
 * @param keys
 * @param config
 * @return {Promise<{success: boolean, status: string, data: any}>}
 */
export async function encrypt({message, keys, config}){
  // assertion
  if (typeof config.encrypt === 'undefined') throw new Error('InvalidConfigForEncryption');

  // compose objects
  const msgObj = importMessage(message);

  // do signing
  let signed = {};
  if (typeof config.sign !== 'undefined' && config.sign.required &&
    (typeof config.encrypt === 'undefined' ||
    (typeof config.encrypt !== 'undefined' && !(config.encrypt.suite === 'openpgp' && config.sign.suite === 'openpgp')))
  ){
    if (keys.suite.sign_verify !== config.sign.suite) throw new Error('UnmatchedKeyTypeToSigningSuite');
    signed = await signBase({
      message: msgObj, keys, options: config.sign.options
    }).catch((e) => { throw new Error(`SigningFailed: ${e.message}`); });
  }
  // console.log(signed);

  // do encryption.
  if (keys.suite.encrypt_decrypt !== config.encrypt.suite) throw new Error('UnmatchedKeyTypeToEncryptionSuite');
  const encrypted = await encryptBase({
    message: msgObj, keys, options: config.encrypt.options
  }).catch( (e) => { throw new Error(`EncryptionFailed: ${e.message}`); });

  // console.log(encrypted);

  return Object.assign(encrypted, signed);
}

/**
 * Decrypt given message and additionally verify attached signatures simultaneously.
 * @param data
 * @param keys
 * @return {Promise<*>}
 */
export async function decrypt({data, keys}){
  if(typeof data.message === 'undefined') throw new Error('InvalidEncryptedDataFormat');

  // do decryption
  if (keys.suite.encrypt_decrypt !== data.message.suite) throw new Error('UnmatchedKeyTypeToEncryptionSuite');
  const decrypted = await decryptBase({
    encrypted: data, keys, options: data.message.options
  }).catch( (e) => { throw new Error(`DecryptionFailed: ${e.message}`); });

  // do verification
  let verified = {};
  if(typeof data.signature !== 'undefined' && keys.keys.publicKeys) {
    verified = await verifyBase({
      message: importMessage(decrypted.data), signature: data.signature, keys, options: data.signature.options
    }).catch((e) => { throw new Error(`VerificationFailed: ${e.message}`); });
  }
  else if (typeof decrypted.signatures !== 'undefined') verified = decrypted.signatures;

  return {data: decrypted.data, signatures: verified};
}

/**
 * Returns the signature objects.
 * @param message
 * @param keys
 * @param config
 * @return {Promise<{success: boolean, status: string, data}>}
 */
export async function sign({message, keys, config}){
  // assertion
  if (typeof config.sign === 'undefined') throw new Error('InvalidConfigForSigning');

  // compose objects
  const msgObj = importMessage(message);

  // do signing
  let signed;
  if(keys.keys.privateKeys) {
    signed = await signBase({
      message: msgObj, keys, options: config.sign.options, output: {sign: config.sign.output}
    }).catch((e) => {
      throw new Error(`SigningFailed: ${e.message}`);
    });
  } else throw new Error('InvalidPrivateKeys');

  return signed;
}

export async function verify({message, signature, keys}){
  // assertion
  if (typeof signature === 'undefined') throw new Error('InvalidObjectForSignature');

  const msgObj = importMessage(message);

  // do verification
  let verified = {};
  if(typeof signature !== 'undefined' && keys.keys.publicKeys) {
    verified = await verifyBase({
      message: msgObj, signature, keys, options: signature.options
    }).catch((e) => {
      throw new Error(`VerificationFailed: ${e.message}`);
    });
  } else throw new Error('InvalidSignatureOrInvalidPublicKey');

  return verified;
}

////////////////////////////////////////////////////////////////////////////
// base functions
const encryptBase = async ({message, keys, options}) => {
  if (!keys.canEncrypt()) throw new Error('UnsupportedKeyForEncryption');

  let suiteObj;
  if (keys.suite.encrypt_decrypt === 'jscu') suiteObj = jscu;
  else if (keys.suite.encrypt_decrypt === 'openpgp') suiteObj = openpgp;
  else throw new Error('UnknownEncryptionSuite');

  return suiteObj.encrypt({ message, keys: keys.keys, options });
};

const decryptBase = async ({encrypted, keys, options}) => {
  if(!keys.canDecrypt()) throw new Error('UnsupportedKeyForDecryption');

  let suiteObj;
  if (keys.suite.encrypt_decrypt === 'jscu') suiteObj = jscu;
  else if (keys.suite.encrypt_decrypt === 'openpgp') suiteObj = openpgp;
  else throw new Error('UnknownDecryptionSuite');

  return suiteObj.decrypt({ encrypted, keys: keys.keys, options });
};

const signBase = async ({message, keys, options}) => {
  if (!keys.canSign()) throw new Error('UnsupportedKeyForSign');

  let suiteObj;
  if (keys.suite.sign_verify === 'jscu') suiteObj = jscu;
  else if (keys.suite.sign_verify === 'openpgp') suiteObj = openpgp;
  else throw new Error('UnknownSigningSuite');

  return suiteObj.sign({ message, keys: keys.keys, options });
};

const verifyBase = async ({message, signature, keys, options}) => {
  if(!keys.canVerify()) throw new Error('UnsupportedKeyForVerification');

  let suiteObj;
  if (keys.suite.sign_verify === 'jscu') suiteObj = jscu;
  else if (keys.suite.sign_verify === 'openpgp') suiteObj = openpgp;
  else throw new Error('UnknownSigningSuite');

  return suiteObj.verify({ message, signature, keys: keys.keys, options});
};