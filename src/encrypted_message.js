/**
 * encrypted_message.js
 */

import {KeyId, KeyIdList, createKeyId, createKeyIdList} from './keyid.js';
import jseu from 'js-encoding-utils';
import cloneDeep from 'lodash.clonedeep';
import msgpack from 'msgpack-lite';

const suites = ['jscu', 'openpgp'];
const keyTypes = ['public_key_encrypt', 'session_key_encrypt'];


export const importEncryptedBuffer = (serialized) => {
  if (!(serialized instanceof Uint8Array)) throw new Error('NonUint8ArraySerializedData');
  let des;
  try {
    des = msgpack.decode(serialized);
  } catch (e) { throw new Error(`FailedToParseEncryptedMessageBuffer: ${e.message}`); }

  if (!des.suite || !des.keyType || !des.message || !des.options) throw new Error('InvalidEncryptedMessageFormat');

  const messageList = des.message.map( (elem) => {
    let keyId;
    if(elem.keyId instanceof Array) keyId = createKeyIdList(elem.keyId.map( (k) => createKeyId(new Uint8Array(k))));
    else keyId = createKeyId(new Uint8Array(elem.keyId));
    return createRawEncryptedMessage(elem.data, keyId, elem.params);
  });

  return createEncryptedMessage( des.suite, des.keyType, messageList, des.options );
};

export const importRawEncryptedBufferList = (array) => {
  if (!(array instanceof Array)) throw new Error('NotArrayOfSerializedData');
  array.forEach( (ser) => {
    if(!(ser instanceof Uint8Array)) throw new Error('NotUint8ArraySerializedData');
  });
  let deserializedArray;
  try {
    deserializedArray = array.map( (ser) => {
      const decoded = msgpack.decode(ser);
      let keyId;
      if(decoded.keyId instanceof Array) keyId = createKeyIdList(decoded.keyId.map( (k) => createKeyId(new Uint8Array(k))));
      else keyId = createKeyId(new Uint8Array(decoded.keyId));
      return createRawEncryptedMessage(decoded.data, keyId, decoded.params);
    });
  } catch (e) { throw new Error(`FailedToParseRawEncryptedMessage: ${e.message}`); }

  return deserializedArray;
};


export const createEncryptedMessage = (suite, keyType, message, options = {}) => {
  // assertion
  if (suites.indexOf(suite) < 0) throw new Error('UnsupportedSuite');
  if (keyTypes.indexOf(keyType) < 0) throw new Error('UnsupportedKeyType');

  return new EncryptedMessage(suite, keyType, message, options);
};

export const createRawEncryptedMessage = (data, keyId, params) => {
  if (!(data instanceof Uint8Array)) throw new Error('NonUint8ArrayData');
  if (!(keyId instanceof KeyId) && !(keyId instanceof KeyIdList)) throw new Error('NonKeyIdOrKeyIdListObject');

  return new RawEncryptedMessage(data, keyId, params);
};

export class EncryptedMessage {
  constructor(suite, keyType, message, options = {}) {
    this._suite = suite;
    this._keyType = keyType;
    this._setMessage(message);
    this._options = options;
  }

  _setMessage(message) {
    this._message = new RawEncryptedMessageList();
    this._message._set(message);
  }

  extract() {
    const returnArray = cloneDeep(this._message);
    this._message = new RawEncryptedMessageList();
    this._message._set([]);
    return returnArray.toArray();
  }

  insert(messageArray) {
    this._message = new RawEncryptedMessageList();
    this._message._set(messageArray);
  }

  get suite() { return this._suite; }
  get keyType() { return this._keyType; }
  get message() { return this._message; }
  get options() { return this._options; }

  serialize() {
    return msgpack.encode({
      suite: this._suite,
      keyType: this._keyType,
      message: this._message.toJsObject(),
      options: this._options
    });
  }
}

export class RawEncryptedMessage extends Uint8Array {
  constructor(data, keyId, params = {}) {
    super(data);
    this._keyId = keyId;
    this._params = params;
  }

  toBase64() { return jseu.encoder.encodeBase64(this); }

  toBuffer() {
    const buf = new Uint8Array(this);
    return cloneDeep(buf);
  }

  toJsObject() {
    return {
      data: this.toBuffer(),
      keyId: this._keyId.toBuffer(),
      params: this._params
    };
  }

  serialize() {
    return msgpack.encode(this.toJsObject());
  }

  get keyId() { return this._keyId; }
  get params() { return this._params; }
}

export class RawEncryptedMessageList extends Array {
  _set(message) {
    if (!(message instanceof Array)) throw new Error('InvalidEncryptedMessageList');
    const binaryMessage = message.map((m) => {
      if (!(m instanceof RawEncryptedMessage)) throw new Error('NotEncryptedMessage');
      return m;
    });
    this.push(...binaryMessage);
  }

  toJsObject() { return this.map((raw) => raw.toJsObject()); }
  toArray() { return Array.from(this); }

  map(callback) { return this.toArray().map(callback); }
  filter(callback) { return this.toArray().filter(callback); }
}
