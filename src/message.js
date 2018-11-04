/**
 * message.js
 */

import jseu from 'js-encoding-utils';
import {KeyId} from './keyid';

export function importMessage(msg){
  const obj = new Message(msg);
  return obj;
}

export function importEncryptedObject(encryptedMessageObj){
// TODO for external encrypted message import
}

class Message {
  constructor(msg){
    this._setMessage(msg);
  }

  _setMessage (msg) {
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

class encryptedMessage {

}

export class RawEncryptedMessage extends Uint8Array {
  constructor(data, keyId, params = {}){
    if(!(data instanceof Uint8Array)) throw new Error('NonUint8ArrayData');
    if(!(keyId instanceof KeyId)) throw new Error('NonKeyIdObject');

    super(data);
    this._keyId = keyId;
    this._params = params;
  }

  toBase64 () { return jseu.encoder.encodeBase64(this); }
  toBuffer () { return new Uint8Array(this); }

  get keyId () { return this._keyId; }
  get params () { return this._params; }
}

class RawEncryptedMessageList extends Array {
  constructor(list){
    super();
  }
}