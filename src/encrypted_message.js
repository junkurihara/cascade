/**
 * encrypted_message.js
 */

import {KeyId, KeyIdList} from './keyid.js';
import jseu from 'js-encoding-utils';
import cloneDeep from 'lodash.clonedeep';
import msgpack from 'msgpack-lite';

const suites = ['jscu', 'openpgp'];
const keyTypes = ['public_key_encrypt', 'session_key_encrypt'];

export function createEncryptedMessage(suite, keyType, message, options = {}) {
  // assertion
  if (suites.indexOf(suite) < 0) throw new Error('UnsupportedSuite');
  if (keyTypes.indexOf(keyType) < 0) throw new Error('UnsupportedKeyType');

  return new EncryptedMessage(suite, keyType, message, options);
}

export function createRawEncryptedMessage(data, keyId, params) {
  if (!(data instanceof Uint8Array)) throw new Error('NonUint8ArrayData');
  if (!(keyId instanceof KeyId) && !(keyId instanceof KeyIdList)) throw new Error('NonKeyIdOrKeyIdListObject');

  return new RawEncryptedMessage(data, keyId, params);
}

class EncryptedMessage {
  constructor(suite, keyType, message, options = {}) {
    this._suite = suite;
    this._keyType = keyType;
    this._setMessage(message);
    this._options = options;
  }

  _setMessage(message) {
    this._message = new RawEncryptedMessageList(message);
  }

  get suite() { return this._suite; }

  get keyType() { return this._keyType; }

  get message() { return this._message; }

  get options() { return this._options; }

  serialize() {
    return msgpack.encode({
      suite: this._suite,
      keyType: this._keyType,
      message: Array.from(this._message).map((raw) => raw.toJsObject()),
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
      keyId: this._keyId,
      params: this._params
    };
  }

  serialize() {
    return msgpack.encode(this.toJsObject());
  }

  get keyId() { return this._keyId; }

  get params() { return this._params; }
}

class RawEncryptedMessageList extends Array {
  constructor(message) {
    super();
    this._set(message);
  }

  _set(message) {
    if (!(message instanceof Array)) throw new Error('InvalidEncryptedMessageList');
    const binaryMessage = message.map((m) => {
      if (!(m instanceof RawEncryptedMessage)) throw new Error('NotEncryptedMessage');
      return m;
    });
    this.push(...binaryMessage);
  }
}