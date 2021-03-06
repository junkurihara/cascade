/**
 * cascaded_data.js
 */

import msgpack from 'msgpack-lite';
import {importEncryptedBuffer, EncryptedMessage} from './encrypted_message.js';
import {importSignatureBuffer, Signature} from './signature.js';

export const importCascadedBuffer = (serialized) => {
  if (!(serialized instanceof Uint8Array)) throw new Error('NonUint8ArraySerializedData');
  let des;
  try {
    des = msgpack.decode(serialized);
  } catch (e) { throw new Error(`FailedToParseCascadedBuffer: ${e.message}`); }

  if (!(des instanceof Array)) throw new Error('InvalidCascadedData');

  const desComponentList = des.map( (obj) => {
    const returnObject = {};
    if(typeof obj.message !== 'undefined') returnObject.message = importEncryptedBuffer(obj.message);
    if(typeof obj.signature !== 'undefined') returnObject.signature = importSignatureBuffer(obj.signature);
    return returnObject;
  });

  return createCascadedData(desComponentList);
};

export const createCascadedData = (data) => {
  // assertion
  if (!(data instanceof Array)) throw new Error('NotArrayForCascadedData');
  data.map( (obj) => {
    if(typeof obj.message !== 'undefined' && !(obj.message instanceof EncryptedMessage)) throw new Error('InvalidEncryptedMessage');
    if(typeof obj.signature !== 'undefined' && !(obj.signature instanceof Signature)) throw new Error('InvalidSignature');
    if(typeof obj.message === 'undefined' && typeof obj.signature === 'undefined') throw new Error('NoEncryptedMessageAndSignature');
  });

  return new CascadedData(data);
};

export class CascadedData extends Array {
  constructor(data){
    super();
    this.push(...data);
  }

  extract(idx) {
    if (idx > this.length -1 || idx < 0) throw new Error('InvalidIndexOutOfRange');
    if (typeof this[idx].message === 'undefined') throw new Error('MessageObjectDoesNotExist');

    return this[idx].message.extract();
  }

  insert(idx, message) {
    if (idx > this.length -1 || idx < 0) throw new Error('InvalidIndexOutOfRange');
    if (!(message instanceof Array)) throw new Error('InvalidEncryptedMessageArray');
    if (this[idx].message.length > 0) throw new Error('MessageAlreadyExists');

    this[idx].message.insert(message);
  }

  serialize() {
    const serializedCompArray = this.map( (obj) => {
      const returnObject = {};
      if (typeof obj.message !== 'undefined') returnObject.message = new Uint8Array(obj.message.serialize());
      if (typeof obj.signature !== 'undefined') returnObject.signature = new Uint8Array(obj.signature.serialize());
      return returnObject;
    });
    const returnArray = msgpack.encode(serializedCompArray);
    return new Uint8Array(returnArray);
  }

  toArray() { return Array.from(this); }

  map(callback) { return Array.from(this).map(callback); }
}
