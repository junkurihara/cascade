/**
 * utils.js
 */

import params from './config.js';

export const getJscu = () => {
  let jscu;
  if (typeof window !== 'undefined' && typeof window.jscu !== 'undefined'){
    jscu = window.jscu;
  }
  else{
    try {
      jscu = require('js-crypto-utils');
    } catch(e) {
      throw new Error(`FailedToLoadJSCU: ${e.message}`);
    } // work around
  }
  return jscu;
};

export const getOpenPgp = () => {
  // load openpgp
  let openpgp;
  let workerPath;
  if(typeof window !== 'undefined' && typeof window.openpgp !== 'undefined') {
    openpgp = window.openpgp;
    workerPath = params.openpgp.workerPathWeb;
  }
  else {
    openpgp = require('openpgp');
    workerPath = params.openpgp.workerPathNode;
    // const path = require('path');
    // workerPath = path.join(path.resolve(), openpgpDefault.WORKER_PATH);
  }

  // initialize openpgp
  try {
    openpgp.initWorker({path: workerPath}); // set the relative web worker path
  } catch(e) {
    console.error(e.message);
  }
  openpgp.config.aead_protect = true; // activate fast AEAD mode (not yet OpenPGP standard)
  openpgp.config.aead_mode = openpgp.enums.aead.eax; // Default, native AES-EAX mode (AEAD)
  openpgp.config.prefer_hash_algorithm = openpgp.enums.hash.sha512; // use SHA512 (default SHA256)
  openpgp.config.encryption_cipher = openpgp.enums.symmetric.aes256; // use AES256
  openpgp.config.compression = openpgp.enums.compression.zlib; // compression prior to encrypt with zlib
  openpgp.config.integrity_protect = true;
  openpgp.config.rsa_blinding = true;
  openpgp.config.show_version = false;
  openpgp.config.show_comment = false;

  return openpgp;
};
