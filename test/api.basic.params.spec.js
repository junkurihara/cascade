import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const cascade = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

describe(`${env}: public key signing/verification`, () => {

  let message;

  before(async function () {
    this.timeout(50000);
    message = new Uint8Array(32);
    for (let i = 0; i < 32; i++) message[i] = 0xFF & i;
  });

  const testString = 'test string';
  it('check if cascade.config can be changed correctly',  async () => {
    cascade.config.openpgp.workerPathWeb = testString;
    expect(cascade.config.openpgp.workerPathWeb === testString).to.be.true;
  });


});