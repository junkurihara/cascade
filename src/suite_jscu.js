/**
 * suite_jscu.js
 */

import {Suite} from './suite.js';
import {getJscu} from './util.js';
import * as utilKeyId from './keyid.js';
import config from './config.js';
import {createEncryptedMessage, createRawEncryptedMessage} from './encrypted_message.js';
import {createSignature, createRawSignature} from './signature.js';

export class Jscu extends Suite {
  /**
   * Generate publicKeyPair or sessionKeyObject with js-crypto-utils.
   * @param params {Object}
   * @param passphrase {string}
   * @param encryptOptions {Object}
   * @return {Promise<*>}
   */
  static async generateKey({params, passphrase=null, encryptOptions={}}) {
    const jscu = getJscu();

    if (params.type === 'session') {
      if (!params.length) throw new Error('params.length must be specified');
      const rawKey = await jscu.random.getRandomBytes(params.length);
      const keyId = await utilKeyId.fromRawKey(rawKey);
      return { key: rawKey, keyId };
    }
    else if (params.type === 'ec' || params.type === 'rsa') {
      const keyType = (params.type === 'ec') ? 'EC' : 'RSA';
      const options = (params.type === 'ec') ? {namedCurve: params.curve} : {modulusLength: params.modulusLength};

      const keyObject = await jscu.pkc.generateKey(keyType, options);

      const keyId = await utilKeyId.fromJscuKey(keyObject.publicKey);

      // for encrypted keys
      if (passphrase) {
        const encryptedDer = await keyObject.privateKey.export('der', {encryptParams: Object.assign({passphrase}, encryptOptions)});
        keyObject.privateKey  = new jscu.Key('der', encryptedDer);
      }

      return { publicKey: keyObject.publicKey, privateKey: keyObject.privateKey, keyId };
    }
    else throw new Error('JscuUnsupportedKeyType');
  }

  /**
   * Import jscu key object
   * @param type
   * @param key
   * @param passphrase
   * @return {Promise<jscu.Key>}
   */
  static async importKey(type, key, passphrase){
    const jscu = getJscu();

    const keyObj = new jscu.Key(type, key);

    if(keyObj.isPrivate && keyObj.isEncrypted){
      if(!passphrase) throw new Error('PassphraseRequired');
      await keyObj.decrypt(passphrase).catch( (e) => {
        throw new Error(`FailedToDecryptPrivateKey: ${e.message}`);
      });
    }

    return keyObj;
  }

  /**
   * Encrypt plaintext object with given keys.
   * @param message
   * @param keys
   * @param options
   * @return {Promise<{message: EncryptedMessage}>}
   */
  static async encrypt({message, keys, options}) {
    const jscu = getJscu();

    // check options
    if(typeof options === 'undefined') options = {};

    // encryption
    let encrypted;
    let encryptedObject;
    if (keys.publicKeys) { // public key encryption

      if(options.privateKeyPass){ // for ECDH TODO: Reconsider if the pem formatted key could be assumed.
        options.privateKey = await Jscu.importKey('pem', options.privateKeyPass.privateKey, options.privateKeyPass.passphrase);
        delete options.privateKeyPass;
      }

      // for ecdh ephemeral keys
      if(!options.privateKey) {
        const jwk = await keys.publicKeys[0].export('jwk'); // TODO KeyType and curves should be retrieved directly from the object?
        if (jwk.kty === 'EC'){
          const ephemeral = await jscu.pkc.generateKey('EC', {namedCurve: jwk.crv});
          options.privateKey = ephemeral.privateKey;
        }
      }

      encrypted = await Promise.all(keys.publicKeys.map( async (publicKeyObj) => {
        const data = await jscu.pkc.encrypt(message.binary, publicKeyObj, options);
        const fed = new Uint8Array(data.data);
        delete data.data;
        return createRawEncryptedMessage(fed, await utilKeyId.fromJscuKey(publicKeyObj), data);
      }));

      // for ecdh, remove private key and add public key in encryption config, and add the config to the encrypted object
      if(typeof options.privateKey !== 'undefined'){
        options.publicKey = await options.privateKey.export('der', {outputPublic: true}); // export public key from private key
        delete options.privateKey;
      }

      encryptedObject = {message: createEncryptedMessage('jscu', 'public_key_encrypt', encrypted, options)};
    }
    else if (keys.sessionKey) { // symmetric key encryption
      if(options.name === 'AES-GCM') {  // TODO: other iv-required algorithms
        const iv = await jscu.random.getRandomBytes(config.jscu.ivLengthAesGcm);
        const data = await jscu.aes.encrypt(message.binary, keys.sessionKey, {name: options.name, iv});
        const keyId = await utilKeyId.fromRawKey(keys.sessionKey);
        const obj = createRawEncryptedMessage(data, keyId, {iv});
        encrypted = [obj]; // TODO, should be an Array?
      }
      else throw new Error('JscuInvalidEncryptionAlgorithm');
      encryptedObject = {message: createEncryptedMessage('jscu', 'session_key_encrypt', encrypted, options)};
    }
    else throw new Error('JscuInvalidEncryptionKey');

    return encryptedObject;
  }

  /**
   * Decrypt encrypted object with given keys.
   * @param encrypted
   * @param keys
   * @param options
   * @return {Promise<{data: *}>}
   */
  static async decrypt({encrypted, keys, options}) {
    if (typeof encrypted.message === 'undefined') throw new Error('InvalidEncryptedMessage'); // TODO, change according to the class
    if (!(encrypted.message.message instanceof Array)) throw new Error('NonArrayMessage');
    const jscu = getJscu();

    let decrypted;
    ////////////////////////////////////////////////////////////////////
    if (encrypted.message.keyType === 'public_key_encrypt'){
      // public key decryption
      if (!keys.privateKeys) throw new Error('JscuPrivateKeyRequired');
      if (options.publicKey){
        options.publicKey = await Jscu.importKey('der', options.publicKey);
      }

      // function definition
      const decryptMessageObject = async (msgObject, privateKeyObject) => {
        const data = msgObject.toBuffer();
        const salt = (typeof msgObject.params.salt !== 'undefined') ? msgObject.params.salt : undefined;
        const iv = (typeof msgObject.params.iv !== 'undefined') ? msgObject.params.iv : undefined;
        const decOptions = Object.assign({ salt, iv }, options);
        return await jscu.pkc.decrypt(data, privateKeyObject, decOptions);
      };

      // filter by keyId
      const msgKeySet = [];
      await Promise.all(keys.privateKeys.map( async (pk) => {
        const keyId = await utilKeyId.fromJscuKey(pk);
        const filtered = encrypted.message.message.filter( (m) => (m.keyId.toHex() === keyId.toHex()));
        msgKeySet.push(...filtered.map((m) => ({message: m, privateKey: pk}) ));
      }));
      if (msgKeySet.length === 0) throw new Error('UnableToDecryptWithGivenPrivateKey');
      // decrypt
      let errMsg = '';
      const decryptedArray = await Promise.all(msgKeySet.map( async (set) => {
        const d = await decryptMessageObject(set.message, set.privateKey).catch( (e) => { errMsg = e.message; });
        if(d) return d;
        else return null;
      }));
      const returnArray = decryptedArray.filter( (d) => (d !== null));

      if(returnArray.length > 0) decrypted = returnArray[0];
      else throw new Error(errMsg);

    }
    ////////////////////////////////////////////////////////////////////
    else if (encrypted.message.keyType === 'session_key_encrypt'){
      // session key decryption
      if (!keys.sessionKey) throw new Error('JscuSessionKeyRequired');
      if (!(encrypted.message.message instanceof Array)) throw new Error('NonArrayMessage');

      const message = encrypted.message.message[0]; // TODO Should be an array?
      const iv = (typeof message.params.iv !== 'undefined') ? message.params.iv : null;

      if(options.name === 'AES-GCM') {
        decrypted = await jscu.aes.decrypt(
          message.toBuffer(),
          keys.sessionKey,
          {name: keys.sessionKey.algorithm, iv}
        );
      }
      else throw new Error('JscuInvalidEncryptionAlgorithm');
    }
    else throw new Error('JscuInvalidKeyType_NotSessionKey');

    return {data: decrypted};
  }

  /**
   * Signing on a message with given private key's'
   * @param message
   * @param keys
   * @param options
   * @return {Promise<{signature: Signature}>}
   */
  static async sign({message, keys, options}){
    if(!keys.privateKeys) throw new Error('JscuInvalidSigningKeys');

    const jscu = getJscu();

    const signatures = await Promise.all(keys.privateKeys.map( async (privKey) => {
      const signature = await jscu.pkc.sign(message.binary, privKey, options.hash, Object.assign({format: 'raw'}, options));
      const keyId = await utilKeyId.fromJscuKey(privKey);

      return createRawSignature(signature, keyId);
    }));

    return {signature: createSignature('jscu', 'public_key_sign', signatures, options) };
  }

  /**
   * Verify signature here
   * @param message
   * @param signature
   * @param keys
   * @param options
   * @return {Promise<{keyId: *, valid: *}[]>}
   */
  static async verify({message, signature, keys, options}){
    if(!keys.publicKeys) throw new Error('JscuInvalidVerificationKeys');

    const jscu = getJscu();

    const signatureKeySet = [];
    const unverified = [];
    await Promise.all(keys.publicKeys.map( async (pk) => {
      const keyId = await utilKeyId.fromJscuKey(pk);
      const filtered = signature.signatures.filter( (s) => {
        if(s.keyId.toHex() === keyId.toHex()) return true;
        else{
          unverified.push({keyId: s.keyId, valid: undefined});
          return false;
        }
      }); // WA
      signatureKeySet.push(...filtered.map((s) => ({signature: s, publicKey: pk}) ));
    }));

    const verified = await Promise.all(signatureKeySet.map( async (sigKey) => {
      const valid = await jscu.pkc.verify(
        message.binary,
        sigKey.signature.toBuffer(),
        sigKey.publicKey,
        options.hash,
        Object.assign({format: 'raw'}, options)
      );
      return {keyId: sigKey.signature.keyId, valid};
    }));

    return verified.concat(unverified);
  }
}