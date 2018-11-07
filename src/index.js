/**
 * index.js
 */

import {
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify
} from './core.js';
import { importKeys } from './keys.js';
import { createEncryptionCascade, createDecryptionCascade } from './cascade.js';

export default {
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify,
  importKeys,
  createEncryptionCascade,
  createDecryptionCascade
};
export {
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify,
  importKeys,
  createEncryptionCascade,
  createDecryptionCascade
};