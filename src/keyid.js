/**
 * keyid.js
 */

import jseu from 'js-encoding-utils';
import config from './config.js';
import {getJscu} from './util.js';
import cloneDeep from 'lodash.clonedeep';

/**
 * Calculate key Id from jwk-formatted key
 * Key id is defined as jwk public key thumbprint (NOTE: not private key thumbprint)
 * see the spec here => https://tools.ietf.org/html/rfc7638
 * @param keyObject
 * @param len
 * @return {Promise<KeyId>}
 */
export const fromJscuKey = async (keyObject, len=config.publicKeyIdLEN) => {
  const thumbPrintBuf = await keyObject.getJwkThumbprint(config.publicKeyIdHash, 'binary');
  return createKeyId(thumbPrintBuf.slice(0, len));
};

/**
 * Just a hash of raw binary key
 * @param bin
 * @param len
 * @return {Promise<KeyId>}
 */
export const fromRawKey = async (bin, len = config.sessionKeyIdLength) => {
  const jscu = getJscu();
  const digest = await jscu.hash.compute(bin, config.sessionKeyIdHash);
  return createKeyId(digest.slice(0, len));
};


export const createKeyId = (keyId) => {
  if(!(keyId instanceof Uint8Array)) throw new Error('NotUint8ArrayKeyId');
  const localKeyId = cloneDeep(keyId);
  return new KeyId(localKeyId);
};

export class KeyId extends Uint8Array {
  // eslint-disable-next-line no-useless-constructor
  constructor(keyId){
    super(keyId);
  }

  toHex() { return jseu.encoder.arrayBufferToHexString(this); }
  toBuffer() {
    const buf = new Uint8Array(this);
    return cloneDeep(buf);
  }
}


// NOTE: KeyIdList is used only for EncryptedMessage generated in OpenPGP.
export const createKeyIdList = (keyIds) => {
  const obj = new KeyIdList();
  obj._init(keyIds);
  return obj;
};

export class KeyIdList extends Array {
  _init(keyIds){
    if (!(keyIds instanceof Array)) throw new Error('InvalidKeyIdList');
    const binaryKeyIds = keyIds.map( (k) => {
      if(!(k instanceof KeyId)) throw new Error('NotKeyId');
      return k;
    });
    this.push(...binaryKeyIds);
  }
  toBuffer() { return this.map( (kid) => kid.toBuffer()); }
  toArray() { return Array.from(this); }

  map(callback) { return this.toArray().map(callback); }
}
