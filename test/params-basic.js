/**
 * params-basic.js
 */


import * as cascade from '../src/index.js';

// Encryption and Signing Parameters
const curves = [ 'P-256', 'P-384', 'P-521' ];
const modulusLength = [ 2048, 2048 ];
const userIds = [ 'test@example.com' ];
const paramArray = [{name: 'ec', param: curves}, {name: 'rsa', param: modulusLength}];

const openpgpEncryptConf = { externalKey: true, suite: 'openpgp', options: { detached: true, compression: 'zlib' }};
const openpgpSignConf = {required: true, suite: 'openpgp', options: {}};

const jscuSessionEncryptConf = {externalKey: true, suite: 'jscu', options: {name: 'AES-GCM'}};
const openpgpgSessionEncryptConf = {suite: 'openpgp', options: {algorithm: 'aes256', aead: true, aead_mode: 'eax' }};

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
const openpgpOnetimeSessionEncryptConf = {
  externalKey: false,
  suite: 'openpgp',
  onetimeKey: {keyParams: {type: 'session', length: 32}},
  options: {algorithm: 'aes256', aead: true, aead_mode: 'eax' }
};

const jscuOnetimePublicEncryptConf = {
  externalKey: false,
  suite: 'jscu',
  onetimeKey: {keyParams: {type: 'ec', curve: 'P-256'} },
  options: { hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: '' }
};

const openpgpOnetimePublicEncryptConf = {
  externalKey: false,
  suite: 'openpgp',
  onetimeKey: {userIds: ['user@example.com'], keyParams: {type: 'ec', keyExpirationTime: 0, curve: 'P-256'}},
  options: { detached: true, compression: 'zlib' }
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
    this.KeysGPG.ec = await Promise.all(
      curves.map ( (curve) => cascade.generateKey({suite: 'openpgp', userIds, keyParams: {type: 'ec', keyExpirationTime: 0, curve}}))
    );
    this.Keys.rsa = await Promise.all(
      modulusLength.map ( (ml) => cascade.generateKey({suite: 'jscu', keyParams: {type: 'rsa', modulusLength: ml}}))
    );
    this.KeysGPG.rsa = await Promise.all(
      modulusLength.map (
        (ml) => cascade.generateKey({suite: 'openpgp', userIds, keyParams: {type: 'rsa', keyExpirationTime: 0, modulusLength: ml}}))
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
  get openpgpEncryptConf () { return openpgpEncryptConf; }
  get openpgpSignConf () { return openpgpSignConf; }
  get jscuSessionEncryptConf () { return jscuSessionEncryptConf; }
  get openpgpgSessionEncryptConf () { return openpgpgSessionEncryptConf; }
  get jscuOnetimeSessionEncryptConf () { return jscuOnetimeSessionEncryptConf; }
  get jscuOnetimeSessionEncryptConfWithoutExternalKey () { return jscuOnetimeSessionEncryptConfWithoutExternalKey; }
  get openpgpOnetimeSessionEncryptConf () { return openpgpOnetimeSessionEncryptConf; }
  get jscuOnetimePublicEncryptConf () { return jscuOnetimePublicEncryptConf; }
  get openpgpOnetimePublicEncryptConf () { return openpgpOnetimePublicEncryptConf; }
}

//   defaultEncryptConfig: {
//     encrypt: {
//       suite: 'openpgp',  // 'jscu'
//       options: {
//         detached: true,
//         compression: 'zlib'
//       },
//     },
//     sign: {
//       required: true,
//       suite: 'openpgp', // 'jscu'
//       options: { },
//     }
//   },
//   ////////////////////////////////////////////////////////////
//   defaultProcedure: [
//     // keyParams is set for steps that involves automatic key generation.
//
//     // first step that encrypts the given data
//     // non-last step generates key automatically on site.
//     {
//       encrypt: {
//         suite: 'jscu',
//         onetimeKey: {keyParams: {type: 'session', length: 32}}, // this key encrypts step 1 key
//         options: {name: 'AES-GCM'}
//       },
//       sign: {
//         required: true,
//       }
//     },
//
//     // final step that encrypts the key used in the previous step under the given original key.
//     // last step feeds the given key.
//     {
//       encrypt: {
//         suite: 'openpgp',  // 'jscu'
//         options: {
//           detached: false, // for signing simultaneously with encryption
//           compression: 'zlib'
//         },
//       },
//       sign: {
//         required: true,
//         suite: 'openpgp', // 'jscu'
//         options: { },
//       }
//       // keyParams is unnecessary to be set. key params will be ignored at last step.
//     } // -> output "encrypted decryption key for 1", "key id for 1"
//   ],
// ECC_P521_NO_EXPIRE: {
//     type: 'ECC',
//     curve: 'P-521',
//     keyExpirationTime: 0
//   },
//
//   ECC_P256_EXPIRE_1_WEEK: {
//     type: 'ECC',
//     curve: 'P-256',
//     keyExpirationTime: 604800 // one week just in case
//   },
//
//   SYMMETRIC_AES256_AEAD_EAX:{
//     type: 'SYMMETRIC',
//     length: 32, // in bytes
//     algorithm: 'aes256',
//     aead: true,
//     aead_mode: 'eax'
//   },
//
//   ECDSA_SHA_256: {
//     type: 'ECC',
//     hash: 'SHA-256'
//   },
//
//   SYMMETRIC_AES256_GCM: {
//     type: 'SYMMETRIC',
//     algorithm: 'AES-GCM',
//     length: 32
//   },