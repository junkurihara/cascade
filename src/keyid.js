/**
 * keyid.js
 */

import jseu from 'js-encoding-utils';
import params from './params.js';
import {getJscu} from './util.js';
import cloneDeep from 'lodash.clonedeep';

/**
 * Calculate key id from openpgp key object
 * @param keyObject
 * @param len
 * @return {KeyId}
 */
export function fromOpenPgpKey(keyObject, len=params.publicKeyIdLEN){
  const fp = keyObject.getFingerprint();
  const buf = jseu.encoder.hexStringToArrayBuffer(fp);
  return createKeyId(buf.slice(0, len));
}

/**
 * Calculate key Id from jwk-formatted key
 * Key id is defined as jwk public key thumbprint (NOTE: not private key thumbprint)
 * see the spec here => https://tools.ietf.org/html/rfc7638
 * @param keyObject
 * @param len
 * @return {Promise<KeyId>}
 */
export async function fromJscuKey(keyObject, len=params.publicKeyIdLEN) {
  const thumbPrintBuf = await keyObject.getJwkThumbprint(params.publicKeyIdHash, 'binary');
  return createKeyId(thumbPrintBuf.slice(0, len));
}

/**
 * Just a hash of raw binary key
 * @param bin
 * @param len
 * @return {Promise<KeyId>}
 */
export async function fromRawKey(bin, len = params.sessionKeyIdLength) {
  const jscu = getJscu();
  const digest = await jscu.hash.compute(bin, params.sessionKeyIdHash);
  return createKeyId(digest.slice(0, len));
}


export function createKeyId(keyId){
  if(!(keyId instanceof Uint8Array)) throw new Error('NotUint8ArrayKeyId');
  const localKeyId = cloneDeep(keyId);
  return new KeyId(localKeyId);
}

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

export function createKeyIdList (keyIds) {
  const obj = new KeyIdList();
  obj._init(keyIds);
  return obj;
}

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