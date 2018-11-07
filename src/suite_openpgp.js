/**
 * suite_openpgp.js
 */
import jseu from 'js-encoding-utils';
import {getOpenPgp} from './util.js';
import {Suite} from './suite.js';
import paramsPGP from './params_openpgp.js';
import * as utilKeyId from './keyid.js';
import {createRawSignature, createSignature, RawSignature} from './signature.js';
import {createEncryptedMessage, createRawEncryptedMessage} from './message.js';

export class OpenPGP extends Suite {

  /**
   * Generated OpenPGP Key Object with given key params.
   * @param userIds {Array}
   * @param passphrase {string}
   * @param params {Object}
   * @return {Promise<*>}
   */
  static async generateKey({userIds=paramsPGP.DEFAULT_USER, passphrase=null, params}) {
    const openpgp = getOpenPgp();

    let options;
    switch (params.type) {
    case 'rsa':
      options = {
        userIds,       // multiple user IDs
        numBits: params.modulusLength,// RSA key size
        passphrase,  // protects the private key
        keyExpirationTime: params.keyExpirationTime
      };
      break;
    case 'ec':
      options = {
        userIds,       // multiple user IDs
        curve: paramsPGP.CURVE_LIST[params.curve].name,  // applied the naming rule of jscu
        passphrase,  // protects the private key
        keyExpirationTime: params.keyExpirationTime
      };
      break;
    case 'session':
      options = {
        length: params.length
      };
      break;
    default:
      throw new Error('GPGUnsupportedAlgorithm');
    }

    if (params.type === 'rsa' || params.type === 'ec') {
      const kp = await openpgp.generateKey(options);
      return {
        publicKey: kp.key.toPublic(),
        privateKey: kp.key,
        keyIds: kp.key.getKeys().map((k) => utilKeyId.fromOpenPgpKey(k)) //kp.key.getKeyIds().map( (bid) => bid.toHex())
      };
    }
    else if (params.type === 'session') {
      const rawKey = await openpgp.crypto.random.getRandomBytes(options.length);
      const keyIds = [await utilKeyId.fromRawKey(rawKey)];
      return {key: rawKey, keyIds};
    }
  }

  static async importKey(type, key, passphrase){
    const openpgp = getOpenPgp();

    const read = (type === 'pem')
      ? await openpgp.key.readArmored(key)
      : await openpgp.key.read(key);

    if(read.err) throw new Error(`InvalidOpenPGPKeyFormat: ${read.err}`);

    const keyArray = await Promise.all(read.keys.map(async (keyObject) => {
      if (keyObject.isPrivate() && keyObject.primaryKey.isEncrypted) {
        await keyObject.decrypt(passphrase);
      }
      return keyObject;
    }));

    return (keyArray.length > 1) ? keyArray : keyArray[0];
  }

  /**
   * returns {message: { Message, suite }, signature: { Signature, suite }}
   * if encryption is done simultaneously with signing, no signature id is given because of privacy reason (issuer hiding)
   * @param message
   * @param keys
   * @param options
   * @param output
   * @return {Promise<*>}
   */
  static async encrypt({message, keys, options={}}){
    const openpgp = getOpenPgp();

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

      // construct an encrypted message object
      const internalHexKeyIds = encrypted.message.getEncryptionKeyIds().map( (id) => id.toHex());
      const externalKeyIds = [];
      keys.publicKeys.map( (x) => x.getKeys().map( (k) => { externalKeyIds.push(utilKeyId.fromOpenPgpKey(k));} ) );
      const encryptionKeyId = externalKeyIds.filter( (fp) => internalHexKeyIds.indexOf(fp.toHex().slice(0, 16)) >= 0);
      const encryptedMessage = [
        createRawEncryptedMessage(encrypted.message.packets.write(), utilKeyId.createKeyIdList(encryptionKeyId), {})
      ];
      encryptedObject = {message: createEncryptedMessage('openpgp', 'public_key_encrypt', encryptedMessage, {})};
    }
    else if (keys.sessionKey) { // symmetric key encryption
      const opt = {
        message: msgObj,
        sessionKey: {data: keys.sessionKey, algorithm: options.algorithm}, // for encryption
        privateKeys: signingKeys, // for signing (optional)
        format: 'binary'
      };
      encrypted = await openpgp.encrypt(Object.assign(opt, options));

      // construct an encrypted message object
      const encryptedMessage = [
        createRawEncryptedMessage(encrypted.message.packets.write(), await utilKeyId.fromRawKey(keys.sessionKey), {})
      ];
      encryptedObject = {message: createEncryptedMessage(
        'openpgp', 'session_key_encrypt', encryptedMessage, {algorithm: options.algorithm}
      )};
    }
    else throw new Error('InvalidEncryptionKey');

    let signatureObj = {};
    if (keys.privateKeys && encrypted.signature) { // if detached is true
      const signatureObjectList = OpenPGP._listFromOpenPgpSig(encrypted.signature.packets, signingKeys);
      signatureObj = {signature: createSignature('openpgp', 'public_key_sign', signatureObjectList, {})};
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
  static async decrypt({ encrypted, keys, options = {} }){
    const openpgp = getOpenPgp();

    const message = await openpgp.message.read(encrypted.message.message[0].toBuffer(), false);

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
        sessionKeys: [ {data: keys.sessionKey, algorithm: options.algorithm} ],
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
  static async sign({message, keys, options={}}){
    const openpgp = getOpenPgp();

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
    const signatureObjectList = OpenPGP._listFromOpenPgpSig(signature.signature.packets, keys.privateKeys);
    return {signature: createSignature('openpgp', 'public_key_sign', signatureObjectList, {})};
  }

  /**
   * Returns detached signature with verification result
   * @param message
   * @param signature
   * @param keys
   * @param options
   * @return {Promise<*>}
   */
  static async verify({message, signature, keys, options}){
    const openpgp = getOpenPgp();

    if(!keys.publicKeys) throw new Error('VerificationKeyRequired');
    const list = OpenPGP._ListToOpenPgpSig(Array.from(signature.signatures), keys.publicKeys);
    const msgObj = openpgp.message.fromBinary(message.binary);

    const verified = await Promise.all(list.signatureObjects.map( async (sigKey) => {
      const msg = msgObj.unwrapCompressed();
      const literalDataList = msg.packets.filterByTag(openpgp.enums.packet.literal);
      const signatureList = [sigKey.openpgpSignature];
      const valid = await openpgp.message.createVerificationObjects(signatureList, literalDataList, [sigKey.publicKey], new Date());
      return {keyId: sigKey.signature.keyId, valid: await valid[0].verified};
    }));

    return verified.concat(list.unverified);
  }

  static _listFromOpenPgpSig (signatures, keys) {
    if (!(signatures instanceof Array)) throw new Error('InvalidSignatureList');

    const externalKeyIds = [];
    keys.map( (x) => x.getKeys().map( (k) => { externalKeyIds.push(utilKeyId.fromOpenPgpKey(k));} ) );

    const signatureObjects = [];
    externalKeyIds.map( (fp) => {
      const correspondingSig = signatures.filter( (sig) => sig.issuerKeyId.toHex() === fp.toHex().slice(0,16));
      correspondingSig.map((sig) => {
        signatureObjects.push(createRawSignature(sig.write(), fp));
      });
    });

    return signatureObjects;
  }

  static _ListToOpenPgpSig (signatures, keys) {
    if (!(signatures instanceof Array)) throw new Error('InvalidSignatureList');

    const openpgp = getOpenPgp();

    const openpgpObjects = signatures.map((sig) => {
      if (!(sig instanceof RawSignature)) throw new Error('NotRawSignatureObject');
      const obj = new openpgp.packet.Signature();
      obj.read(sig.toBuffer(), 0, -1);
      return {openpgpSignature: obj, signature: sig};
    });

    const externalKey = [];
    keys.map( (x) => x.getKeys().map( (k) => { externalKey.push({publicKey: k, keyId: utilKeyId.fromOpenPgpKey(k)});} ) );

    const signatureObjects = [];
    externalKey.map( (fp) => {
      const correspondingSig = openpgpObjects.filter( (sig) => sig.openpgpSignature.issuerKeyId.toHex() === fp.keyId.toHex().slice(0,16));
      correspondingSig.map((sig) => {
        signatureObjects.push(Object.assign({publicKey: fp.publicKey}, sig));
      });
    });
    const unverified = [];
    const idArray = signatureObjects.map( (x) => x.openpgpSignature.issuerKeyId.toHex());
    openpgpObjects.map( (sig) => {
      if(idArray.indexOf(sig.openpgpSignature.issuerKeyId.toHex().slice(0,16)) < 0){
        unverified.push({keyId: sig.openpgpSignature.issuerFingerprint, valid: undefined});
      }
    });

    return {signatureObjects, unverified};
  }
}