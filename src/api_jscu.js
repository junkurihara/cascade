/**
 * api_jscu.js
 */

import defaultParams from './params_jscu.js';
import * as util from './util.js';
import {Signature, rawSignature} from './signature.js';
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
    if(options.privateKeyPass){
      options.privateKey = await importKey('pem', options.privateKeyPass.privateKey, options.privateKeyPass.passphrase);
      options.privateKey = await options.privateKey.export('jwk');
      delete options.privateKeyPass;
    }
    encrypted = await Promise.all(keys.publicKeys.map( async (publicKeyObj) => {
      const publicJwk = await publicKeyObj.export('jwk');
      return jscu.pkc.encrypt(message.binary, publicJwk, options);
    }));
    encryptedObject = getEncryptedObject('public', encrypted, keys.publicKeys, options);
  }
  else if (keys.sessionKey) { // symmetric key encryption
    const options = {};
    if(keys.sessionKey.algorithm === 'AES-GCM') {  // TODO: other iv-required algorithms
      const iv = await jscu.random.getRandomBytes(defaultParams.RECOMMENDED_IV_LENGTH);
      options.iv = iv;
      encrypted = await jscu.aes.encrypt(message.binary, keys.sessionKey.key, {name: keys.sessionKey.algorithm, iv});
    }
    else throw new Error('JscuInvalidEncryptionAlgorithm');
    encryptedObject = await getEncryptedObject('session', encrypted, keys.sessionKey, options);
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

  const jscu = util.getJscu();

  const keyType = encrypted.message.keyType;

  let decrypted;
  ////////////////////////////////////////////////////////////////////
  if (keyType === 'public_key_encrypt'){
    // public key decryption
    if (!keys.privateKeys) throw new Error('JscuPrivateKeyRequired');
    if (!(encrypted.message.message instanceof Array)) throw new Error('NonArrayMessage');
    if (options.publicKey){
      options.publicKey = await importKey('der', options.publicKey);
      options.publicKey = await options.publicKey.export('jwk');
    }

    // function definition
    const decryptMessageObject = async (msgObject, privateKeyObject) => {
      const data = msgObject.data;
      const salt = (typeof msgObject.salt !== 'undefined') ? msgObject.salt : undefined;
      const iv = (typeof msgObject.iv !== 'undefined') ? msgObject.iv : undefined;
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

    if(!keys.sessionKey) throw new Error('JscuSessionKeyRequired');

    const message = encrypted.message.message;
    const iv = (typeof encrypted.message.iv !== 'undefined') ? encrypted.message.iv : null;

    decrypted = await jscu.aes.decrypt(
      message,
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
 * @return {Promise<[any , any , any , any , any , any , any , any , any , any]>}
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
    return Object.assign(sigKey.signature, {valid});
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
const getEncryptedObject = async (type, message, key, options = {}) => {
  let encryptionKeyType;
  let encryptedMessage;
  const encryptionOptions = {};

  if (type === 'public') {
    encryptionKeyType = 'public_key_encrypt';

    // get encryption key ids
    const keyIds = await Promise.all( key.map( async (k) => fromJscuKey(k)));
    encryptedMessage = message.map( (m, idx) => Object.assign(m, {keyId: keyIds[idx]}) );
    encryptionOptions.options = Object.assign({}, options);

    // for ecdh, remove private key and add public key in encryption config, and add the config to the encrypted object
    if(typeof encryptionOptions.options.privateKey !== 'undefined'){
      const jscu = util.getJscu();
      const publicKey = new jscu.Key('jwk', encryptionOptions.options.privateKey);
      encryptionOptions.options.publicKey = await publicKey.export('der', {outputPublic: true}); // export public key from private key
      delete encryptionOptions.options.privateKey;
    }
  }
  else if (type === 'session'){
    encryptionKeyType = 'session_key_encrypt';
    encryptionOptions.keyIds = [{
      digest: await fromRawKey(key.key),
      algorithm: key.algorithm
    }];
    if(options.iv) encryptionOptions.iv = options.iv;
    encryptedMessage = message;
  }
  else throw new Error('JscuInvalidKeyType');

  return {
    message: Object.assign({
      suite: 'jscu',
      keyType: encryptionKeyType,
      message: encryptedMessage,
    }, encryptionOptions)
  };
};
