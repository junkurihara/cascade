import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const core = testEnv.library;
const env = testEnv.envName;

import chai from 'chai';
// const should = chai.should();
const expect = chai.expect;

describe(`${env}: public and private key pair generation test`, () => {
  const curves = [ 'P-256', 'P-384', 'P-521' ];
  const modulusLength = [ 2048, 4096 ];
  const userIds = [ 'kurihara@zettant.com' ];

  it('JSCU EC public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'ec', curve}};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // console.log(keyArray);
  });

  it('JSCU protected EC public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'ec', curve}, passphrase: 'omg'};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // console.log(keyArray);
  });

  it('JSCU RSA public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( modulusLength.map ( (ml) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'rsa', modulusLength: ml}};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // console.log(keyArray);
  });

  it('JSCU protected RSA public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( modulusLength.map ( (ml) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'rsa', modulusLength: ml}, passphrase: 'omg'};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // keyArray.map( (x) => {console.log(x);});
  });

  it('JSCU symmetric session key generation', async function (){
    this.timeout(5000);
    const keyParam = {suite: 'jscu', keyParams: {type: 'session', length: 32}};
    const key = await core.generateKey(keyParam);
    expect((key.key instanceof Uint8Array) && (key.key.length === 32)).to.be.true;
    // console.log(key);
  });

});
