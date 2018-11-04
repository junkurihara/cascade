import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const core = testEnv.library;
const env = testEnv.envName;

import mixProcedureHybrid from './procs/procedure_mix-hybrid.js';
import keys from './sample_keys.js';

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;


describe(`${env}: Encryption test with mixed encryption algorithms using OpenPGP and JSCU, and detached signatures`, () => {
  let msg;
  let pemKeys;
  before(async () => {
    msg = new Uint8Array(32);
    for (let i = 0; i < 32; i++) msg[i] = 0xFF & i;

    pemKeys = await core.generateKey({suite: 'jscu', keyParams: {type: 'ECC', curve: 'P-256'}});
  });

  it('Mixed Hybrid: message should be successfully encrypted and decrypted', async function (){
    this.timeout(5000);
    const sortedKeys = {
      publicKeys: keys.publicKeys, // openpgp for encryption
      privateKeyPassSets:[ { privateKey: pemKeys.privateKey.keyString, passphrase: '' } ] // naive (jscu) for signature
    };
    const sortedDecryptionKeys = {
      publicKeys: [ pemKeys.publicKey.keyString ],
      privateKeyPassSets: keys.privateKeyPassSets
    };

    const encrypted = await core.encryptSeq({message: msg, keys: sortedKeys, procedureConfig: mixProcedureHybrid.procedure});
    console.log(encrypted);
    expect(encrypted.success).to.be.true;
    const decrypted = await core.decryptSeq({encryptedArray: encrypted.data, keys: sortedDecryptionKeys});
    console.log(decrypted);
    expect(decrypted.success).to.be.true;
  });
});
