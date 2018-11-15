/**
 * core.js
 */

import {generateKeyObject} from './keys.js';
import {importMessage} from './message.js';
import {OpenPGP} from './suite_openpgp.js';
import {Jscu} from './suite_jscu.js';

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
  if (keyParams.keyParams.type === 'session') {
    return keyObj;
  }
  else {
    if(keyParams.suite === 'openpgp') { /** OpenPGP **/
      return {
        publicKey: { keyString: keyObj.publicKey.armor(), keyId: keyObj.keyId },
        privateKey: Object.assign(
          { keyString: keyObj.privateKey.armor(), keyId: keyObj.keyId },
          (keyParams.passphrase) ? {passphrase: keyParams.passphrase} : {})
      };
    }
    else if (keyParams.suite === 'jscu') { /** js-crypto-utils **/
      return {
        publicKey: {
          keyString: await keyObj.publicKey.export('pem', {outputPublic: true}),
          keyId: keyObj.keyId
        },
        privateKey: Object.assign(
          { keyString: await keyObj.privateKey.export('pem'), keyId: keyObj.keyId },
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
  if (!keys.canEncrypt()) throw new Error('UnsupportedKeyForEncryption');

  // compose objects
  const msgObj = importMessage(message);

  // do signing
  let signed = {};
  if (typeof config.sign !== 'undefined' && config.sign.required &&
    (typeof config.encrypt === 'undefined' ||
    (typeof config.encrypt !== 'undefined' && !(config.encrypt.suite === 'openpgp' && config.sign.suite === 'openpgp')))
  ){
    if (keys.suite.sign_verify !== config.sign.suite) throw new Error('UnmatchedKeyTypeToSigningSuite');
    if (!keys.canSign()) throw new Error('UnsupportedKeyForSign');
    signed = await cryptoSuite(keys.suite.sign_verify).sign({
      message: msgObj, keys: keys.keys, options: config.sign.options
    }).catch((e) => {
      throw new Error(`SigningFailed: ${e.message}`);
    });
  }

  // do encryption.
  if (keys.suite.encrypt_decrypt !== config.encrypt.suite) throw new Error('UnmatchedKeyTypeToEncryptionSuite');
  const encrypted = await cryptoSuite(keys.suite.encrypt_decrypt).encrypt({
    message: msgObj, keys: keys.keys, options: config.encrypt.options
  }).catch( (e) => { throw new Error(`EncryptionFailed: ${e.message}`); });
  // const encrypted = await encryptBase({
  //   message: msgObj, keys, options: config.encrypt.options
  // }).catch( (e) => { throw new Error(`EncryptionFailed: ${e.message}`); });

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
  if(!keys.canDecrypt()) throw new Error('UnsupportedKeyForDecryption');

  // do decryption
  if (keys.suite.encrypt_decrypt !== data.message.suite) throw new Error('UnmatchedKeyTypeToEncryptionSuite');
  const decrypted = await cryptoSuite(keys.suite.encrypt_decrypt).decrypt({
    encrypted: data, keys: keys.keys, options: data.message.options
  }).catch( (e) => { console.error(e); throw new Error(`DecryptionFailed: ${e.message}`); });
  // const decrypted = await decryptBase({
  //   encrypted: data, keys, options: data.message.options
  // }).catch( (e) => { console.error(e); throw new Error(`DecryptionFailed: ${e.message}`); });

  // do verification
  let verified = {};
  if(typeof data.signature !== 'undefined' && keys.keys.publicKeys && keys.canVerify()) {
    verified = await cryptoSuite(keys.suite.sign_verify).verify({
      message: importMessage(decrypted.data),
      signature: data.signature,
      keys: keys.keys,
      options: data.signature.options
    }).catch((e) => {
      throw new Error(`VerificationFailed: ${e.message}`);
    });
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
  if (!keys.canSign()) throw new Error('UnsupportedKeyForSign');

  // compose objects
  const msgObj = importMessage(message);

  // do signing
  if(keys.keys.privateKeys) {
    return await cryptoSuite(keys.suite.sign_verify).sign({
      message: msgObj, keys: keys.keys, options: config.sign.options
    }).catch((e) => {
      throw new Error(`SigningFailed: ${e.message}`);
    });
  } else throw new Error('InvalidPrivateKeys');
}

/**
 * Returns verification result
 * @param message
 * @param signature
 * @param keys
 * @return {Promise<*>}
 */
export async function verify({message, signature, keys}){
  // assertion
  if (typeof signature === 'undefined') throw new Error('InvalidObjectForSignature');
  if (!keys.canVerify()) throw new Error('UnsupportedKeyForVerification');

  const msgObj = importMessage(message);

  // do verification
  if(typeof signature !== 'undefined' && keys.keys.publicKeys) {
    return await cryptoSuite(keys.suite.sign_verify).verify({
      message: msgObj, signature, keys: keys.keys, options: signature.options
    }).catch((e) => {
      throw new Error(`VerificationFailed: ${e.message}`);
    });
  } else throw new Error('InvalidSignatureOrInvalidPublicKey');
}

const cryptoSuite = (suiteName) => {
  let suiteObj;
  if (suiteName === 'jscu') suiteObj = Jscu;
  else if (suiteName === 'openpgp') suiteObj = OpenPGP;
  else throw new Error('UnknownSuite');
  return suiteObj;
};

////////////////////////////////////////////////////////////////////////////
// base functions
// const encryptBase = async ({message, keys, options}) => {
//   if (!keys.canEncrypt()) throw new Error('UnsupportedKeyForEncryption');
//
//   const suiteObj = cryptoSuite(keys.suite.encrypt_decrypt);
//
//   return suiteObj.encrypt({ message, keys: keys.keys, options });
// };

// const decryptBase = async ({encrypted, keys, options}) => {
//   if(!keys.canDecrypt()) throw new Error('UnsupportedKeyForDecryption');
//
//   const suiteObj = cryptoSuite(keys.suite.encrypt_decrypt);
//
//   return suiteObj.decrypt({ encrypted, keys: keys.keys, options });
// };