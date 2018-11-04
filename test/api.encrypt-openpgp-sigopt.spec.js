import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const core = testEnv.library;
const env = testEnv.envName;

import opgpProcedureSingleEmbed from './procs/procedure_openpgp-single-embedsig.js';
import opgpProcedureSingleNoSig from './procs/procedure_openpgp-single-nosig.js';
import keys from './sample_keys.js';

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

describe(`${env}: OpenPGP encryption test with embedded signatures and without signatures`, () => {
  let msg;
  before(async () => {
    msg = new Uint8Array(32);
    for (let i = 0; i < 32; i++) msg[i] = 0xFF & i;
  });


  it('OpenPGP Single: Message should be successfully encrypted and decrypted with embedded signature', async function () {
    this.timeout(5000);
    const encrypted = await core.encryptSeq({message: msg, keys, procedureConfig: opgpProcedureSingleEmbed.procedure});
    console.log(encrypted);
    expect(encrypted.success).to.be.true;
    const decrypted = await core.decryptSeq({encryptedArray: encrypted.data, keys});
    expect(decrypted.success).to.be.true;
    console.log(decrypted);
  });

  it('OpenPGP Single: Message should be successfully encrypted and decrypted without signature', async function () {
    this.timeout(5000);
    const noPriv = {publicKeys: keys.publicKeys};
    const noPub = {privateKeyPassSets: keys.privateKeyPassSets};

    const encrypted = await core.encryptSeq({message: msg, keys: noPriv, procedureConfig: opgpProcedureSingleNoSig.procedure});
    console.log(encrypted);
    expect(encrypted.success).to.be.true;
    const decrypted = await core.decryptSeq({encryptedArray: encrypted.data, keys: noPub});
    expect(decrypted.success).to.be.true;
    console.log(decrypted);
  });

});
