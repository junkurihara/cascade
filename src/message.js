/**
 * message.js
 */

import jseu from 'js-encoding-utils';
import cloneDeep from 'lodash/cloneDeep';
import {KeyId, KeyIdList} from './keyid.js';

/**
 * import message and translate it to message object.
 * @param msg
 * @return {Message}
 */
export function importMessage(msg){
  const localMessage = cloneDeep(msg);
  const obj = new Message();
  obj._init(localMessage);
  return obj;
}

class Message {
  _init(msg){
    if(msg instanceof Uint8Array){
      this._message = msg;
      this._messageType = 'binary';
    }
    else if (typeof msg === 'string'){
      this._message = jseu.encoder.stringToArrayBuffer(msg);
      this._messageType = 'string';
    }
    else throw new Error('UnsupportedMessageType');
  }

  get binary () { // returns message in binary format
    return this._message;
  }

  get message () { // return message in original format
    if(this.messageType === 'binary') return this._message;
    else if (this.messageType === 'string') return jseu.encoder.arrayBufferToString(this._message);
    else return null;
  }
  get messageType () { return this._messageType; }

  set signature (sig) { this._signature = sig; } // will be removed
  get signature () { return this._signature; } // will be removed
}

const suites = ['jscu', 'openpgp'];
const keyTypes = ['public_key_encrypt', 'session_key_encrypt'];

export function createEncryptedMessage(suite, keyType, message, options = {}){
  // assertion
  if(suites.indexOf(suite) < 0) throw new Error('UnsupportedSuite');
  if(keyTypes.indexOf(keyType) < 0) throw new Error('UnsupportedKeyType');

  return new EncryptedMessage(suite, keyType, message, options);
}

export function createRawEncryptedMessage (data, keyId, params) {
  if(!(data instanceof Uint8Array)) throw new Error('NonUint8ArrayData');
  if(!(keyId instanceof KeyId) && !(keyId instanceof KeyIdList)) throw new Error('NonKeyIdOrKeyIdListObject');

  return new RawEncryptedMessage(data, keyId, params);
}

class EncryptedMessage {
  constructor(suite, keyType, message, options = {}){

    this._suite = suite;
    this._keyType = keyType;
    this._setMessage(message);
    this._options = options;
  }

  _setMessage(message){
    this._message = new RawEncryptedMessageList(message);
  }

  get suite () { return this._suite; }
  get keyType () { return this._keyType; }
  get message () { return this._message; }
  get options () { return this._options; }
}

export class RawEncryptedMessage extends Uint8Array {
  constructor(data, keyId, params = {}){
    super(data);
    this._keyId = keyId;
    this._params = params;
  }

  toBase64 () { return jseu.encoder.encodeBase64(this); }
  toBuffer () {
    const buf = new Uint8Array(this);
    return new Uint8Array(buf);
  }

  get keyId () { return this._keyId; }
  get params () { return this._params; }
}

class RawEncryptedMessageList extends Array {
  constructor(message){
    super();
    this._set(message);
  }

  _set(message){
    if (!(message instanceof Array)) throw new Error('InvalidEncryptedMessageList');
    const binaryMessage = message.map( (m) => {
      if(!(m instanceof RawEncryptedMessage)) throw new Error('NotEncryptedMessage');
      return m;
    });
    this.push(...binaryMessage);
  }
}