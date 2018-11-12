/**
 * signature
 */
import {KeyId} from './keyid.js';
import jseu from 'js-encoding-utils';
import cloneDeep from 'lodash.clonedeep';
import msgpack from 'msgpack-lite';
import {createKeyId} from './keyid';

const suites = ['jscu', 'openpgp'];
const keyTypes = ['public_key_sign'];

export function importSignatureBuffer(serialized){
  if (!(serialized instanceof Uint8Array)) throw new Error('NonUint8ArraySerializedData');
  let des;
  try {
    des = msgpack.decode(serialized);
  } catch (e) { throw new Error(`FailedToParseSignatureBuffer: ${e.message}`); }

  if (!des.suite || !des.keyType || !des.signatures || !des.options) throw new Error('InvalidSignatureFormat');

  const signatureList = des.signatures.map( (elem) => createRawSignature(elem.data, createKeyId(elem.keyId)) );

  return createSignature(des.suite, des.keyType, signatureList, des.options );
}

export function createSignature(suite, keyType, signatures, options = {}){
  // assertion
  if(suites.indexOf(suite) < 0) throw new Error('UnsupportedSuite');
  if(keyTypes.indexOf(keyType) < 0) throw new Error('UnsupportedKeyType');
  if(suite === 'jscu' && typeof options.hash === 'undefined') throw new Error('HashMustBeSpecified');
  if (!(signatures instanceof Array)) throw new Error('InvalidSignatureList');

  return new Signature(suite, keyType, signatures, options);
}

export class Signature {
  constructor(suite, keyType, signatures, options = {}){
    this._suite = suite;
    this._keyType = keyType;
    this._signatures = new SignatureList(signatures);
    this._options = options;
  }

  get suite () { return this._suite; }
  get keyType () { return this._keyType; }
  get signatures () { return this._signatures; }
  get options () { return this._options; }

  serialize () {
    return msgpack.encode({
      suite: this._suite,
      keyType: this._keyType,
      signatures: this._signatures.toJsObject(),
      options: this._options
    });
  }
}

class SignatureList extends Array {
  constructor(signatures){
    super();
    const binarySignatures = signatures.map( (sig) => {
      if(!(sig instanceof RawSignature)) throw new Error('NotRawSignatureObject');
      return sig;
    });
    this.push(...binarySignatures);
  }

  toJsObject() { return this.map( (s) => s.toJsObject() ); }
  toArray() { return Array.from(this); }

  map(callback) { return this.toArray().map(callback); }
  filter(callback) { return this.toArray().filter(callback); }
}

export function createRawSignature(sig, keyId){
  // assertion
  if(!(sig instanceof Uint8Array)) throw new Error('NonUint8ArraySignature');
  if(!(keyId instanceof KeyId)) throw new Error('NonKeyIdObject');

  return new RawSignature(sig, keyId);
}

export class RawSignature extends Uint8Array {
  constructor(sig, keyId){
    super(sig);
    this._keyId = keyId;
  }

  toBase64 () { return jseu.encoder.encodeBase64(this); }
  toBuffer () { const buf = new Uint8Array(this);
    return cloneDeep(buf);
  }
  toJsObject () {
    return {
      data: this.toBuffer(),
      keyId: this._keyId.toBuffer(),
    };
  }

  get keyId () { return this._keyId; }
}