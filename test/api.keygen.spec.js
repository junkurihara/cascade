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

  it('OpenPGP key generation with passphrase', async function () {
    this.timeout(5000);

    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'openpgp', userIds, passphrase: 'omg', keyParams: {type: 'ECC', keyExpirationTime: 0, curve}};
      return core.generateKey(keyParam);
    }) );
    // console.log(keyArray);
    const ok = keyArray.every( (k) => !!k.privateKey.passphrase);
    expect(ok).to.be.true;
  });

  it('OpenPGP key generation without passphrase', async function () {
    this.timeout(5000);

    const baseParam = { type: 'ECC', keyExpirationTime: 0 };

    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'openpgp', userIds, keyParams: Object.assign(baseParam, {curve})};
      return core.generateKey(keyParam);
    }) );
    // console.log(keyArray);
    const ng = keyArray.every( (k) => !k.privateKey.passphrase);
    expect(ng).to.be.true;
  });

  it('JSCU EC public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'ECC', curve}};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // console.log(keyArray);
  });

  it('JSCU protected EC public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'ECC', curve}, passphrase: 'omg'};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // console.log(keyArray);
  });

  it('JSCU RSA public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( modulusLength.map ( (ml) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'RSA', modulusLength: ml}};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // console.log(keyArray);
  });

  it('JSCU protected RSA public key pair generation', async function () {
    this.timeout(5000);
    let success = true;
    const keyArray = await Promise.all( modulusLength.map ( (ml) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'RSA', modulusLength: ml}, passphrase: 'omg'};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).to.be.true;
    // keyArray.map( (x) => {console.log(x);});
  });

  it('OpenPGP symmetric session key generation', async function (){
    this.timeout(5000);
    const keyParam = {suite: 'openpgp', keyParams: {type: 'SYMMETRIC', length: 32}};
    const key = await core.generateKey(keyParam);
    expect((key.key instanceof Uint8Array) && (key.key.length === 32)).to.be.true;
    // console.log(key);
  });


  it('JSCU symmetric session key generation', async function (){
    this.timeout(5000);
    const keyParam = {suite: 'jscu', keyParams: {type: 'SYMMETRIC', length: 32}};
    const key = await core.generateKey(keyParam);
    expect((key.key instanceof Uint8Array) && (key.key.length === 32)).to.be.true;
    // console.log(key);
  });

});