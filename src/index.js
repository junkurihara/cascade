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
import { createEncryptionCascade, createDecryptionCascade } from './cascade.js';
import { importKeys } from './keys.js';
import { importEncryptedBuffer } from './encrypted_message.js';
import { importSignatureBuffer } from './signature.js';
import { importCascadedBuffer} from './cascaded_data.js';

export default {
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify,
  importKeys,
  importEncryptedBuffer,
  importSignatureBuffer,
  importCascadedBuffer,
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
  importEncryptedBuffer,
  importSignatureBuffer,
  importCascadedBuffer,
  createEncryptionCascade,
  createDecryptionCascade
};