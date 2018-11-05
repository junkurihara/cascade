import {decryptSingle, encryptParallel} from './cascade';
import params from './params';
import * as openpgp from './api_openpgp';
import * as jscu from './api_jscu';

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
        keyArrObj.publicKeys = await Promise.all(keys.publicKeys.map((pk) => openpgp.importKey('pem', pk)));
      if (keys.sessionKey) keyArrObj.sessionKey = keys.sessionKey; // symmetric key
      if (keys.privateKeyPassSets && mode === 'decrypt')
        keyArrObj.privateKeys = await Promise.all(keys.privateKeyPassSets.map(async (pkps) => {
          if (pkps.privateKey instanceof Uint8Array) return openpgp.importKey('der', pkps.privateKey, pkps.passphrase);
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
        keyArrObj.privateKeys = await Promise.all(keys.privateKeyPassSets.map(async (pkps) => {
          if (pkps.privateKey instanceof Uint8Array) return openpgp.importKey('der', pkps.privateKey, pkps.passphrase);
          else return openpgp.importKey('pem', pkps.privateKey, pkps.passphrase);
        })); //await readPrivateOpenPGP(keys.privateKeyPassSets); // privateKey
      if (keys.publicKeys && mode === 'decrypt')
        keyArrObj.publicKeys = await Promise.all(keys.publicKeys.map((pk) => openpgp.importKey('pem', pk)));
      break;
    }
    case 'jscu': {
      /** js-crypto-utils **/
      if (keys.privateKeyPassSets && mode === 'encrypt') keyArrObj.privateKeys =
          await Promise.all(
            keys.privateKeyPassSets.map((pkps) => jscu.importKey('pem', pkps.privateKey, pkps.passphrase))
          );
      if (keys.publicKeys && mode === 'decrypt') keyArrObj.publicKeys =
          await Promise.all(
            keys.publicKeys.map((pk) => jscu.importKey('pem', pk))
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

/**
 * Decrypt encrypted array object with given keys.
 * @param encryptedArray {Array}
 * @param keys {Object}
 * @return {Promise<*>}
 */
export async function decryptSeq({encryptedArray, keys}) {
  // TODO: AssertionとDefaultParamsの処理、try+catchとメイン関数だけ残す形にする。
  // default params
  console.debug('invoke decryption');

  // import original keys
  const getImportedKeys = async (keyObj, encrypted) => {
    // specs
    const originalSpec = {encrypt: {suite: encrypted.message.suite}};
    if (encrypted.signature && keyObj.publicKeys) originalSpec.sign = {suite: encrypted.signature.suite}; // detached signature
    else if (keyObj.publicKeys) originalSpec.sign = {suite: encrypted.message.suite}; // embedded signature
    // key import as suite-specific key object
    return importKey(keyObj, originalSpec, 'decrypt');
  };


  // serialized decryption
  // TODO: This should be xbrid.decryptSerial in cascade.js
  const originalKeys = await getImportedKeys(keys, encryptedArray[encryptedArray.length - 1]);
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
    return Object.assign({success: validity, status: (validity) ? 'OK' : 'ValidationFailure'}, decrypted.message);
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
export async function encryptSeq({message, keys, procedureConfig}) {
  console.debug('invoke encryption');
  // assertion
  if (!Array.isArray(procedureConfig)) throw new Error('NonArrayProcedure');
  if (!procedureConfig.length) throw new Error('EmptyProcedure');

  // default params
  if (!procedureConfig) procedureConfig = params.defaultProcedure;

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