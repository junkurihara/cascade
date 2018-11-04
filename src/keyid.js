/**
 * keyid.js
 */

import jseu from 'js-encoding-utils';
import params from './params.js';
import {getJscu} from './util.js';

/**
 * Calculate key id from openpgp key object
 * @param keyObject
 * @param len
 * @return {KeyId}
 */
export function fromOpenPgpKey(keyObject, len=params.publicKeyIdLEN){
  const fp = keyObject.getFingerprint();
  const buf = jseu.encoder.hexStringToArrayBuffer(fp);
  return new KeyId(buf.slice(0, len));
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
  return new KeyId(thumbPrintBuf.slice(0, len));
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
  return new KeyId(digest.slice(0, len));
}

export class KeyId extends Uint8Array {
  constructor(keyId){
    if(!(keyId instanceof Uint8Array)) throw new Error('NotUint8ArrayKeyId');
    super(keyId);
  }

  toHex() { return jseu.encoder.arrayBufferToHexString(this); }
}