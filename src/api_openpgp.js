/**
 * api_openpgp.js
 */

import jseu from 'js-encoding-utils';
import openpgpDefault from './params_openpgp.js';
import * as util from './util.js';
import {fromOpenPgpKey, fromRawKey} from './keyid.js';
import {rawSignature, Signature} from './signature';
import {RawEncryptedMessage} from './message';

/**
 *
 * @param userIds
 * @param passphrase
 * @param params
 * @return {Promise<*>}
 */
export async function generateKey({userIds=openpgpDefault.DEFAULT_USER, passphrase=null, params}){
  const openpgp = util.getOpenPgp();

  let options;
  switch (params.type) {
  case 'RSA':
    options = {
      userIds,       // multiple user IDs
      numBits: params.modulusLength,// RSA key size
      passphrase,  // protects the private key
      keyExpirationTime: params.keyExpirationTime
    };
    break;
  case 'ECC':
    options = {
      userIds,       // multiple user IDs
      curve: openpgpDefault.CURVE_LIST[params.curve].name,  // applied the naming rule of jscu
      passphrase,  // protects the private key
      keyExpirationTime: params.keyExpirationTime
    };
    break;
  case 'SYMMETRIC':
    options = {
      length: params.length
    };
    break;
  default:
    throw new Error('GPGUnsupportedAlgorithm');
  }

  if(params.type === 'RSA' || params.type === 'ECC') {
    const kp = await openpgp.generateKey(options);
    return {
      publicKey: kp.key.toPublic(),
      privateKey: kp.key,
      keyIds: kp.key.getKeys().map( (k) => fromOpenPgpKey(k)) //kp.key.getKeyIds().map( (bid) => bid.toHex())
    };
  }
  else if(params.type === 'SYMMETRIC') {
    const rawKey = await openpgp.crypto.random.getRandomBytes(options.length);
    const keyIds = [ await fromRawKey(rawKey) ];
    return { key: rawKey, keyIds };
  }
}

// for armored = 'pem' / unarmored = 'der' key importing
export async function importKey (type, key, passphrase){
  const openpgp = util.getOpenPgp();

  const read = (type === 'pem')
    ? await openpgp.key.readArmored(key)
    : await openpgp.key.read(key);

  if(read.err){
    console.log(key);
    console.log(type);
    console.error(read.err);
    throw new Error('InvalidOpenPGPKeyFormat');
  }

  const keyArray = await Promise.all(read.keys.map(async (keyObject) => {
    if (keyObject.isPrivate() && keyObject.primaryKey.isEncrypted) {
      await keyObject.decrypt(passphrase);
    }

    return keyObject;
  }));

  return (keyArray.length > 1) ? keyArray : keyArray[0];
}

/**
 * returns {message: { message, suite, keyIds: {type: [ids]}, signature: {signature, suite, keyIds: {type: [ids]} }}
 * if encryption is done simultaneously with signing, no signature id is given because of privacy reason (issuer hiding)
 * @param message
 * @param keys
 * @param options
 * @param output
 * @return {Promise<*>}
 */
export async function encrypt({message, keys, options={}}){
  const openpgp = util.getOpenPgp();

  // check options
  if(options.compression) options.compression = openpgp.enums.compression[options.compression];
  options.armor = false; // armor must be false to get key ids after encryption.

  // convert message
  const msgObj = openpgp.message.fromBinary(message.binary);

  // check signing key format to do signing simultaneously with encryption
  let signingKeys;
  if(typeof keys.privateKeys !== 'undefined'
    && keys.privateKeys instanceof Array
    && keys.privateKeys[0] instanceof openpgp.key.Key) signingKeys = keys.privateKeys;

  // encryption
  let encrypted;
  let encryptedObject;
  if(keys.publicKeys){ // public key encryption
    const opt = {
      message: msgObj,
      publicKeys: keys.publicKeys, // for encryption
      privateKeys: signingKeys, // for signing (optional)
      format: 'binary'
    };
    encrypted = await openpgp.encrypt(Object.assign(opt, options));
    encryptedObject = await getEncryptedObject('public', encrypted.message, keys.publicKeys, {});
  }
  else if (keys.sessionKey) { // symmetric key encryption
    const opt = {
      message: msgObj,
      sessionKey: {data: keys.sessionKey.key, algorithm: keys.sessionKey.algorithm}, // for encryption
      privateKeys: signingKeys, // for signing (optional)
      format: 'binary'
    };
    encrypted = await openpgp.encrypt(Object.assign(opt, options));
    encryptedObject = await getEncryptedObject('session', encrypted.message, keys.sessionKey, {algorithm: keys.sessionKey.algorithm});
  }
  else throw new Error('InvalidEncryptionKey');

  let signatureObj = {};
  if (keys.privateKeys && encrypted.signature) { // if detached is true
    // signatureObj = getDetachedSignatureObject(encrypted.signature, signingKeys);
    const signatureObjectList = listFromOpenPgpSig(encrypted.signature.packets, signingKeys);
    signatureObj = {signature: new Signature('openpgp', 'public_key_sign', signatureObjectList, {})};
  }

  return Object.assign(encryptedObject, signatureObj);
}


/**
 * Decrypt Openpgp encrypted message
 * @param encrypted
 * @param keys
 * @param options
 * @return {Promise<*>}
 */
export async function decrypt({ encrypted, keys, options = {} }){
  const openpgp = util.getOpenPgp();

  const message = await openpgp.message.read(encrypted.message.message, false);

  let decrypted;
  if(encrypted.message.keyType === 'public_key_encrypt'){
    decrypted = await openpgp.decrypt(Object.assign({
      message,
      privateKeys: keys.privateKeys,
      publicKeys: keys.publicKeys,
      format: 'binary'
    }, options));
  }
  else if (encrypted.message.keyType === 'session_key_encrypt'){
    decrypted = await openpgp.decrypt(Object.assign({
      message,
      sessionKeys: [ {data: keys.sessionKey.key, algorithm: keys.sessionKey.algorithm} ],
      publicKeys: keys.publicKeys,
      format: 'binary'
    }, options));
  }

  decrypted.data = new Uint8Array(decrypted.data);

  if (decrypted.signatures instanceof Array){
    decrypted.signatures = decrypted.signatures.map( (sig) => {
      const short = sig.keyid.toHex();
      const long = sig.signature.packets.map( (s) => new Uint8Array(s.issuerFingerprint));
      const filtered = long.filter((l) => short === jseu.encoder.arrayBufferToHexString(l).slice(0, 16) );
      if (filtered.length === 0) throw new Error('SomethingWrongInOpenPGPSignature');
      return {keyId: filtered[0], valid: sig.valid};
    });
  }

  return decrypted;
}

/**
 * Returns detached signature
 * @param message
 * @param keys
 * @param options
 * @param output
 * @return {Promise<*>}
 */
export async function sign({message, keys, options={}}){
  const openpgp = util.getOpenPgp();

  // check options
  options.detached = true; // this must be always true for individual signature
  options.armor = false; // this must be always false to get key ids

  const msgObj = openpgp.message.fromBinary(message.binary);

  if(!keys.privateKeys) throw new Error('SigningKeyRequired');
  const opt = {
    message: msgObj,
    privateKeys: keys.privateKeys // for signing (optional)
  };
  const signature = await openpgp.sign(Object.assign(opt, options));
  const signatureObjectList = listFromOpenPgpSig(signature.signature.packets, keys.privateKeys);
  return {signature: new Signature('openpgp', 'public_key_sign', signatureObjectList, {})};
}

/**
 * Returns detached signature with verification result
 * @param message
 * @param signature
 * @param keys
 * @param options
 * @return {Promise<*>}
 */
export async function verify({message, signature, keys, options}){
  const openpgp = util.getOpenPgp();

  if(!keys.publicKeys) throw new Error('VerificationKeyRequired');
  const sigKeyList = ListToOpenPgpSig(Array.from(signature.signatures), keys.publicKeys);
  const msgObj = openpgp.message.fromBinary(message.binary);

  return await Promise.all(sigKeyList.map( async (sigKey) => {
    const msg = msgObj.unwrapCompressed();
    const literalDataList = msg.packets.filterByTag(openpgp.enums.packet.literal);
    const signatureList = [sigKey.openpgpSignature];
    const valid = await openpgp.message.createVerificationObjects(signatureList, literalDataList, [sigKey.publicKey], new Date());
    return {keyId: sigKey.signature.keyId, valid: await valid[0].verified};
  }));
}


/**
 * Encrypted message object is formatted here
 * {message: { message, suite, type = 'encrypt|encrypt_session', keyIds}, signature: {signature, suite, type=sign, keyIds} }
 * @param type
 * @param message
 * @param key
 * @param options
 * @return {*}
 */
const getEncryptedObject = async (type, message, key=null, options) => {
  let encryptionKeyType;
  let encryptionKeyId;
  if(type === 'public'){
    encryptionKeyType = 'public_key_encrypt';
    const internalHexKeyIds = message.getEncryptionKeyIds().map( (id) => id.toHex());
    const externalKeyIds = [];
    key.map( (x) => x.getKeys().map( (k) => { externalKeyIds.push(fromOpenPgpKey(k));} ) );
    encryptionKeyId = externalKeyIds.filter( (fp) => internalHexKeyIds.indexOf(fp.toHex().slice(0, 16)) >= 0);
  }
  else if (type === 'session'){
    encryptionKeyType = 'session_key_encrypt';
    encryptionKeyId = await fromRawKey(key.key);
  }
  else throw new Error('type must be either public or session');

  return {
    message: {
      suite: 'openpgp',
      keyType: encryptionKeyType,
      keyIds: encryptionKeyId,
      message: message.packets.write(),
      options
    }
  };
};

const listFromOpenPgpSig = (signatures, keys) => {
  if (!(signatures instanceof Array)) throw new Error('InvalidSignatureList');

  const externalKeyIds = [];
  keys.map( (x) => x.getKeys().map( (k) => { externalKeyIds.push(fromOpenPgpKey(k));} ) );

  const signatureObjects = [];
  externalKeyIds.map( (fp) => {
    const correspondingSig = signatures.filter( (sig) => sig.issuerKeyId.toHex() === fp.toHex().slice(0,16));
    correspondingSig.map((sig) => {
      signatureObjects.push(new rawSignature(sig.write(), fp));
    });
  });

  return signatureObjects;
};

const ListToOpenPgpSig = (signatures, keys) => {
  if (!(signatures instanceof Array)) throw new Error('InvalidSignatureList');

  const openpgp = util.getOpenPgp();

  const openpgpObjects = signatures.map((sig) => {
    if (!(sig instanceof rawSignature)) throw new Error('NotRawSignatureObject');
    const obj = new openpgp.packet.Signature();
    obj.read(sig.toBuffer(), 0, -1);
    return {openpgpSignature: obj, signature: sig};
  });

  const externalKey = [];
  keys.map( (x) => x.getKeys().map( (k) => { externalKey.push({publicKey: k, keyId: fromOpenPgpKey(k)});} ) );

  const signatureObjects = [];
  externalKey.map( (fp) => {
    const correspondingSig = openpgpObjects.filter( (sig) => sig.openpgpSignature.issuerKeyId.toHex() === fp.keyId.toHex().slice(0,16));
    correspondingSig.map((sig) => {
      signatureObjects.push(Object.assign({publicKey: fp.publicKey}, sig));
    });
  });

  return signatureObjects;
};
