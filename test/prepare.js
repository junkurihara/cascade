/**
 * prepare.js
 */

import common from '../webpack.baseconfig.json';

export function getTestEnv(){
  let envName;
  let message;
  let library;
  if (process.env.TEST_ENV === 'window'){
    if(typeof window !== 'undefined' && typeof window[common.libName] !== 'undefined'){
      envName = 'Window';
      library = window[common.libName];
      message = '**This is a test with a library imported from window.**';
    }
    else throw new Error('The library is not loaded in window object.');
  }
  else {
    envName = 'Source';
    library = require('../src/index');
    message = '**This is a test with source codes in src.**';
  }

  return {library, envName, message};
}
