/**
 * utils.js
 */


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
