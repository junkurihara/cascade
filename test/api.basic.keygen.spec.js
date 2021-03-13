import {getTestEnv} from './prepare.js';
const testEnv = getTestEnv();
const core = testEnv.library;
const env = testEnv.envName;

describe(`${env}: public and private key pair generation test`, () => {
  const curves = [ 'P-256', 'P-384', 'P-521' ];
  const modulusLength = [ 2048, 4096 ];
  const userIds = [ 'kurihara@zettant.com' ];

  it('JSCU EC public key pair generation', async () => {
    let success = true;
    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'ec', curve}};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).toBeTruthy();
    // console.log(keyArray);
  }, 100000);

  it('JSCU protected EC public key pair generation', async () => {
    let success = true;
    const keyArray = await Promise.all( curves.map ( (curve) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'ec', curve}, passphrase: 'omg'};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).toBeTruthy();
    // console.log(keyArray);
  },100000);

  it('JSCU RSA public key pair generation', async () => {
    let success = true;
    const keyArray = await Promise.all( modulusLength.map ( (ml) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'rsa', modulusLength: ml}};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).toBeTruthy();
    // console.log(keyArray);
  },100000);

  it('JSCU protected RSA public key pair generation', async () => {
    let success = true;
    const keyArray = await Promise.all( modulusLength.map ( (ml) => {
      const keyParam = {suite: 'jscu', keyParams: {type: 'rsa', modulusLength: ml}, passphrase: 'omg'};
      return core.generateKey(keyParam);
    }) ).catch( (e) => {console.error(e.message); success = false; });
    expect(success).toBeTruthy();
    // keyArray.map( (x) => {console.log(x);});
  },100000);

  it('JSCU symmetric session key generation', async () => {
    const keyParam = {suite: 'jscu', keyParams: {type: 'session', length: 32}};
    const key = await core.generateKey(keyParam);
    expect((key.key instanceof Uint8Array) && (key.key.length === 32)).toBeTruthy();
    // console.log(key);
  },100000);

});
