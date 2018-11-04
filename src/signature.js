/**
 * signature
 */
import {KeyId} from './keyid';
import * as jseu from 'js-encoding-utils';

const suites = ['jscu', 'openpgp'];
const keyTypes = ['public_key_sign'];

export class Signature {
  constructor(suite, keyType, signatures, options = {}){
    // assertion
    if(suites.indexOf(suite) < 0) throw new Error('UnsupportedSuite');
    if(keyTypes.indexOf(keyType) < 0) throw new Error('UnsupportedKeyType');
    if(suite === 'jscu' && typeof options.hash === 'undefined') throw new Error('HashMustBeSpecified');

    this._suite = suite;
    this._keyType = keyType;
    this._setSignatures(signatures);
    this._options = options;
  }

  _setSignatures(signatures){
    this._signatures = new SignatureList(signatures, this._suite);
  }

  get suite () { return this._suite; }
  get keyType () { return this._keyType; }
  get signatures () { return this._signatures; }
  get options () { return this._options; }

}

class SignatureList extends Array {
  constructor(signatures){
    super();
    this._set(signatures);
  }

  _set(signatures){
    if (!(signatures instanceof Array)) throw new Error('InvalidSignatureList');
    const binarySignatures = signatures.map( (sig) => {
      if(!(sig instanceof rawSignature)) throw new Error('NotRawSignatureObject');
      return sig;
    });
    this.push(...binarySignatures);
  }
}

export class rawSignature extends Uint8Array {
  constructor(sig, keyId){
    if(!(sig instanceof Uint8Array)) throw new Error('NonUint8ArraySignature');
    if(!(keyId instanceof KeyId)) throw new Error('NonKeyIdObject');
    super(sig);
    this._keyId = keyId;
  }

  toBase64 () { return jseu.encoder.encodeBase64(this); }
  toBuffer () { return new Uint8Array(this); }

  get keyId () { return this._keyId; }
}