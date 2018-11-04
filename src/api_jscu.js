/**
 * api_jscu.js
 */

import defaultParams from './params_jscu.js';
import * as util from './util.js';
import {Signature, rawSignature} from './signature.js';
import {RawEncryptedMessage} from './message.js';
import {fromJscuKey, fromRawKey} from './keyid.js';

/**
 * Generate publicKeyPair or sessionKeyObject with js-crypto-utils.
 * @param params {Object}
 * @param passphrase
 * @param encryptOptions
 * @return {Promise<*>}
 */
export async function generateKey({params, passphrase=null, encryptOptions={}}) { //TODO
  const jscu = util.getJscu();

  if (params.type === 'SYMMETRIC') {
    if(!params.length) throw new Error('params.length must be specified');
    const rawKey = await jscu.random.getRandomBytes(params.length);
    const keyIds = [ await fromRawKey(rawKey) ];
    return {
      key: rawKey,
      keyIds
    };
  }
  else if (params.type === 'ECC' || params.type === 'RSA') {
    const keyType = (params.type === 'ECC') ? 'EC' : 'RSA';
    const options = (params.type === 'ECC') ? {namedCurve: params.curve} : {modulusLength: params.modulusLength};

    const jwKeys = await jscu.pkc.generateKey(keyType, options);
    const keyIds = [ await fromJscuKey(new jscu.Key('jwk', jwKeys.publicKey)) ];

    const publicKeyObj = new jscu.Key('jwk', jwKeys.publicKey);
    let privateKeyObj = new jscu.Key('jwk', jwKeys.privateKey);

    // for encrypted keys
    if (passphrase) {
      const encryptedDer = await privateKeyObj.export( 'der', { encryptParams: Object.assign({passphrase}, encryptOptions) });
      privateKeyObj = new jscu.Key('der', encryptedDer);
    }

    return {
      publicKey: publicKeyObj,
      privateKey: privateKeyObj,
      keyIds
    };
  }
  else throw new Error('JscuUnsupportedKeyType');
}

// for jwk/pem/der key importing
export async function importKey (type, key, passphrase){
  const jscu = util.getJscu();
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
 * @return {Promise<{message: {suite: string, keyType: string, keyIds: {digest: *, algorithm: *}[], message: *}}>}
 */
export async function encrypt({message, keys, options}) {
  const jscu = util.getJscu();

  // check options
  if(typeof options === 'undefined') options = {};

  // encryption
  let encrypted;
  let encryptedObject;
  if (keys.publicKeys) { // public key encryption

    if(options.privateKeyPass){ // for ECDH TODO: Reconsider if the pem formatted key could be assumed.
      options.privateKey = await importKey('pem', options.privateKeyPass.privateKey, options.privateKeyPass.passphrase);
      options.privateKey = await options.privateKey.export('jwk');
      delete options.privateKeyPass;
    }

    encrypted = await Promise.all(keys.publicKeys.map( async (publicKeyObj) => {
      const publicJwk = await publicKeyObj.export('jwk');
      const data = await jscu.pkc.encrypt(message.binary, publicJwk, options);
      const fed = new Uint8Array(data.data);
      delete data.data;
      return new RawEncryptedMessage(fed, await fromJscuKey(publicKeyObj), data);
    }));
    encryptedObject = getEncryptedObject('public', encrypted, options);
  }
  else if (keys.sessionKey) { // symmetric key encryption
    const opt = { algorithm: keys.sessionKey.algorithm };
    Object.assign(options, opt);
    if(keys.sessionKey.algorithm === 'AES-GCM') {  // TODO: other iv-required algorithms
      const iv = await jscu.random.getRandomBytes(defaultParams.RECOMMENDED_IV_LENGTH);
      const data = await jscu.aes.encrypt(message.binary, keys.sessionKey.key, {name: keys.sessionKey.algorithm, iv});
      const keyId = await fromRawKey(keys.sessionKey.key);
      const obj = new RawEncryptedMessage(data, keyId, {iv});
      encrypted = [obj]; // TODO, should be an Array?
    }
    else throw new Error('JscuInvalidEncryptionAlgorithm');
    encryptedObject = getEncryptedObject('session', encrypted, options);
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
export async function decrypt({encrypted, keys, options}) {
  if (typeof encrypted.message === 'undefined') throw new Error('InvalidEncryptedMessage'); // TODO, change according to the class
  if (!(encrypted.message.message instanceof Array)) throw new Error('NonArrayMessage');
  const jscu = util.getJscu();

  const keyType = encrypted.message.keyType;

  let decrypted;
  ////////////////////////////////////////////////////////////////////
  if (keyType === 'public_key_encrypt'){
    // public key decryption
    if (!keys.privateKeys) throw new Error('JscuPrivateKeyRequired');
    if (options.publicKey){
      options.publicKey = await importKey('der', options.publicKey);
      options.publicKey = await options.publicKey.export('jwk');
    }

    // function definition
    const decryptMessageObject = async (msgObject, privateKeyObject) => {
      const data = msgObject.toBuffer();
      const salt = (typeof msgObject.params.salt !== 'undefined') ? msgObject.params.salt : undefined;
      const iv = (typeof msgObject.params.iv !== 'undefined') ? msgObject.params.iv : undefined;
      const privateJwk = await privateKeyObject.export('jwk');
      const decOptions = Object.assign({ salt, iv }, options);
      return await jscu.pkc.decrypt(data, privateJwk, decOptions);
    };

    // filter by keyId
    const msgKeySet = [];
    await Promise.all(keys.privateKeys.map( async (pk) => {
      const keyId = await fromJscuKey(pk);
      const filtered = encrypted.message.message.filter( (m) => (m.keyId.toHex() === keyId.toHex()));
      msgKeySet.push(...filtered.map((m) => ({message: m, privateKey: pk}) ));
    }));
    if (msgKeySet.length === 0) throw new Error('UnableToDecryptWithGivenPrivateKey');

    // decrypt
    const decryptedArray = [];
    let errMsg = '';
    await Promise.all(msgKeySet.map( async (set) => {
      const d = await decryptMessageObject(set.message, set.privateKey).catch( (e) => { errMsg = e.message; });
      if(d) decryptedArray.push(d);
    }));

    if(decryptedArray.length > 0) decrypted = decryptedArray[0];
    else throw new Error(errMsg);

  }
  ////////////////////////////////////////////////////////////////////
  else if (keyType === 'session_key_encrypt'){
    // session key decryption
    if (!keys.sessionKey) throw new Error('JscuSessionKeyRequired');
    if (!(encrypted.message.message instanceof Array)) throw new Error('NonArrayMessage');

    const message = encrypted.message.message[0]; //TODO
    const iv = (typeof message.params.iv !== 'undefined') ? message.params.iv : null;

    decrypted = await jscu.aes.decrypt(
      message.toBuffer(),
      keys.sessionKey.key,
      { name: keys.sessionKey.algorithm, iv }
    );
  }
  else throw new Error('JscuInvalidKeyType_NotSessionKey');

  return {data: decrypted};
}

/**
 * Signing on a message with given private key's'
 * @param message
 * @param keys
 * @param options
 * @return {Promise<{signature: {suite: string, keyType: string, signatures: *, options: *}}>}
 */
export async function sign({message, keys, options}){
  if(!keys.privateKeys) throw new Error('JscuInvalidSigningKeys');

  const jscu = util.getJscu();

  const signatures = await Promise.all(keys.privateKeys.map( async (privKey) => {
    const privateJwk = await privKey.export('jwk');
    const signature = await jscu.pkc.sign(message.binary, privateJwk, options.hash, {format: 'raw'});
    const keyId = await fromJscuKey(privKey);

    return new rawSignature(signature, keyId);
  }));

  return {signature: new Signature('jscu', 'public_key_sign', signatures, options) };
}

/**
 * Verify signature here
 * @param message
 * @param signature
 * @param keys
 * @param options
 * @return {Promise<{keyId: *, valid: *}[]>}
 */
export async function verify({message, signature, keys, options}){
  if(!keys.publicKeys) throw new Error('JscuInvalidVerificationKeys');

  const jscu = util.getJscu();

  const signatureKeySet = [];
  await Promise.all(keys.publicKeys.map( async (pk) => {
    const keyId = await fromJscuKey(pk);
    const filtered = Array.from(signature.signatures).filter( (s) => (s.keyId.toHex() === keyId.toHex())); // WA
    signatureKeySet.push(...filtered.map((s) => ({signature: s, publicKey: pk}) ));
  }));

  return await Promise.all(signatureKeySet.map( async (sigKey) => {
    const valid = await jscu.pkc.verify(message.binary, sigKey.signature.toBuffer(), await sigKey.publicKey.export('jwk'), options.hash, {format: 'raw'});
    return {keyId: sigKey.signature.keyId, valid};
  }));
}



/**
 * Compose an encrypted objects from encrypted messages and other supplemental data
 * @param type
 * @param message
 * @param key
 * @param options
 * @return {Promise<*>}
 */
// TODO: EncryptedMessageクラスのインスタンスを吐くように修正
const getEncryptedObject = async (type, message, options = {}) => {
  let encryptionKeyType;

  if (type === 'public') {
    encryptionKeyType = 'public_key_encrypt';

    // for ecdh, remove private key and add public key in encryption config, and add the config to the encrypted object
    if(typeof options.privateKey !== 'undefined'){
      const jscu = util.getJscu();
      const publicKey = new jscu.Key('jwk', options.privateKey);
      options.publicKey = await publicKey.export('der', {outputPublic: true}); // export public key from private key
      delete options.privateKey;
    }
  }
  else if (type === 'session'){
    encryptionKeyType = 'session_key_encrypt';
  }
  else throw new Error('JscuInvalidKeyType');

  return {
    message: {
      suite: 'jscu',
      keyType: encryptionKeyType,
      message,
      options
    }
  };
};
