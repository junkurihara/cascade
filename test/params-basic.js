/**
 * params-basic.js
 */


import * as cascade from '../src/index.js';

// Encryption and Signing Parameters
const curves = [ 'P-256', 'P-384', 'P-521' ];
const modulusLength = [ 2048, 2048 ];
const paramArray = [{name: 'ec', param: curves}, {name: 'rsa', param: modulusLength}];

const jscuSessionEncryptConf = {externalKey: true, suite: 'jscu', options: {name: 'AES-GCM'}};

const jscuOnetimeSessionEncryptConf = {
  externalKey: false,
  suite: 'jscu',
  onetimeKey: {keyParams: {type: 'session', length: 32}},
  options: {name: 'AES-GCM'}
};
const jscuOnetimeSessionEncryptConfWithoutExternalKey = {
  externalKey: true,
  suite: 'jscu',
  onetimeKey: {keyParams: {type: 'session', length: 32}},
  options: {name: 'AES-GCM'}
};

const jscuOnetimePublicEncryptConf = {
  externalKey: false,
  suite: 'jscu',
  onetimeKey: {keyParams: {type: 'ec', curve: 'P-256'} },
  options: { hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: '' }
};

export async function createParam() {
  const param = new ParamsBasic();
  await param.init();
  return param;
}

class ParamsBasic{
  constructor(){
    this.Keys={};
    this.KeysGPG={};
  }

  async init (){
    this.Keys.ec = await Promise.all(
      curves.map ( (curve) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'ec', curve}}))
    );
    this.Keys.rsa = await Promise.all(
      modulusLength.map ( (ml) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'rsa', modulusLength: ml}}))
    );

    let jscu;
    if (typeof window !== 'undefined' && typeof window.jscu !== 'undefined') jscu = window.jscu;
    else {
      try {
        jscu = require('js-crypto-utils');
      } catch(e) {
        throw new Error(`FailedToLoadJSCU: ${e.message}`);
      } // work around
    }
    this.Keys.sessionKey = await jscu.random.getRandomBytes(32);
  }

  jscuEncryptConf (paramObject, idx) {
    return {
      externalKey: true,
      suite: 'jscu',
      options: (paramObject.name === 'ec')
        ? {
          privateKeyPass: {privateKey: this.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}, // only for ECDH
          hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: ''
        }
        : {hash: 'SHA-256'},
    };
  }

  jscuKeyWrappingConf (paramObject, idx) {
    return {
      externalKey: true,
      suite: 'jscu',
      options: (paramObject.name === 'ec')
        ? {
          privateKeyPass: {privateKey: this.Keys[paramObject.name][idx].privateKey.keyString, passphrase: ''}, // only for ECDH
          hash: 'SHA-256', encrypt: 'AES-KW', keyLength: 32, info: ''
        }
        : {hash: 'SHA-256'},
    };
  }

  jscuEncryptConfEphemeral (paramObject) {
    return {
      externalKey: true,
      suite: 'jscu',
      options: (paramObject.name === 'ec') ? { hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: '' } : {hash: 'SHA-256'},
    };
  }

  jscuEncryptConfEphemeralNoExternalKey (paramObject) {
    return {
      suite: 'jscu',
      options: (paramObject.name === 'ec') ? { hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: '' } : {hash: 'SHA-256'},
    };
  }

  jscuSignConf (paramObject) {
    return {
      required: true,
      suite: 'jscu',
      options: (paramObject.name === 'ec') ? {hash: 'SHA-256'} : {hash: 'SHA-256', name: 'RSA-PSS', saltLength: 32}
    };
  }

  get paramArray () { return paramArray; }
  get jscuSessionEncryptConf () { return jscuSessionEncryptConf; }
  get jscuOnetimeSessionEncryptConf () { return jscuOnetimeSessionEncryptConf; }
  get jscuOnetimeSessionEncryptConfWithoutExternalKey () { return jscuOnetimeSessionEncryptConfWithoutExternalKey; }
  get jscuOnetimePublicEncryptConf () { return jscuOnetimePublicEncryptConf; }
}
