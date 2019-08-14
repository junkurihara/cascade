/**
 * core.js
 */

import {generateKeyObject} from './keys.js';
import {importMessage} from './message.js';
import {Jscu} from './suite_jscu.js';

/**
 * Generate key (pair). This API must be called externally.
 * @param keyParams {object}: a parameter to generate keys in the form of like
 * Simple Crypto Suite using WebCryptoAPI/OpenSSL:
 * { suite: 'jscu',
 *   passphrase: 'omg',
 *   keyParams: {type: 'ECC', curve} } }
 * @return {Promise<*>}
 */
export const generateKey = async (keyParams) => {
  const keyObj = await generateKeyObject(keyParams);

  // formatting
  if (keyParams.keyParams.type === 'session') {
    return keyObj;
  }
  else {
    if (keyParams.suite === 'jscu') { /** js-crypto-utils **/
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
};

/**
 * Basic encryption API that enables signing simultaneously with encrypting message.
 * @param message
 * @param keys
 * @param config
 * @return {Promise<{success: boolean, status: string, data: any}>}
 */
export const encrypt = async ({message, keys, config}) => {
  // assertion
  if (typeof config.encrypt === 'undefined') throw new Error('InvalidConfigForEncryption');
  if (!keys.canEncrypt()) throw new Error('UnsupportedKeyForEncryption');

  // compose objects
  const msgObj = importMessage(message);

  // do signing
  let signed = {};
  if (typeof config.sign !== 'undefined' && config.sign.required){
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

  return Object.assign(encrypted, signed);
};

/**
 * Decrypt given message and additionally verify attached signatures simultaneously.
 * @param data
 * @param keys
 * @return {Promise<*>}
 */
export const decrypt = async ({data, keys}) => {
  if(typeof data.message === 'undefined') throw new Error('InvalidEncryptedDataFormat');
  if(!keys.canDecrypt()) throw new Error('UnsupportedKeyForDecryption');

  // do decryption
  if (keys.suite.encrypt_decrypt !== data.message.suite) throw new Error('UnmatchedKeyTypeToEncryptionSuite');
  const decrypted = await cryptoSuite(keys.suite.encrypt_decrypt).decrypt({
    encrypted: data, keys: keys.keys, options: data.message.options
  }).catch( (e) => { console.error(e); throw new Error(`DecryptionFailed: ${e.message}`); });

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
};

/**
 * Returns the signature objects.
 * @param message
 * @param keys
 * @param config
 * @return {Promise<{success: boolean, status: string, data}>}
 */
export const sign = async ({message, keys, config}) => {
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
};

/**
 * Returns verification result
 * @param message
 * @param signature
 * @param keys
 * @return {Promise<*>}
 */
export const verify = async ({message, signature, keys}) => {
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
};

const cryptoSuite = (suiteName) => {
  let suiteObj;
  if (suiteName === 'jscu') suiteObj = Jscu;
  else throw new Error('UnknownSuite');
  return suiteObj;
};
