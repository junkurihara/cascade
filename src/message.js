/**
 * message.js
 */

import jseu from 'js-encoding-utils';
import cloneDeep from 'lodash.clonedeep'; //'lodash/cloneDeep';

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