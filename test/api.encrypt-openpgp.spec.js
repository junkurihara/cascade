import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const core = testEnv.library;
const env = testEnv.envName;

import opgpProcedureTribrid from './procs/procedure_openpgp-tribrid.js';
import opgpProcedureHybrid from './procs/procedure_openpgp-hybrid.js';
import opgpProcedureSingle from './procs/procedure_openpgp-single.js';
import keys from './sample_keys.js';

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

describe(`${env}: OpenPGP encryption test with detached signatures`, () => {
  let msg;
  before(async () => {
    msg = new Uint8Array(32);
    for (let i = 0; i < 32; i++) msg[i] = 0xFF & i;
  });


  it('OpenPGP Single: Message should be successfully encrypted and decrypted', async function () {
    this.timeout(5000);
    const encrypted = await core.encryptSeq({message: msg, keys, procedureConfig: opgpProcedureSingle.procedure});
    console.log(encrypted);
    expect(encrypted.success).to.be.true;
    const decrypted = await core.decryptSeq({encryptedArray: encrypted.data, keys});
    expect(decrypted.success).to.be.true;
    console.log(decrypted);
  });


  it('OpenPGP Hybrid: Message should be successfully encrypted and decrypted', async function () {
    this.timeout(5000);
    const encrypted = await core.encryptSeq({message: msg, keys, procedureConfig: opgpProcedureHybrid.procedure});
    console.log(encrypted);
    expect(encrypted.success).to.be.true;
    const decrypted = await core.decryptSeq({encryptedArray: encrypted.data, keys});
    expect(decrypted.success).to.be.true;
    console.log(decrypted);
  });

  it('OpenPGP Tribrid: Message should be successfully encrypted and decrypted', async function () {
    this.timeout(5000);
    const encrypted = await core.encryptSeq({message: msg, keys, procedureConfig: opgpProcedureTribrid.procedure});
    console.log(encrypted.data[0]);
    expect(encrypted.success).to.be.true;
    const decrypted = await core.decryptSeq({encryptedArray: encrypted.data, keys});
    expect(decrypted.success).to.be.true;
    console.log(decrypted);
  });
});
