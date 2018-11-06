/**
 *
 * ZETTANT CONFIDENTIAL
 * __________________
 *
 *  [2017] - [2018] Zettant Incorporated
 *  All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Zettant Incorporated and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Zettant Incorporated and its
 * suppliers and may be covered by Japan and Foreign Patents,
 * patents in process, and are protected by trade secret or
 * copyright law. Dissemination of this information or
 * reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Zettant Incorporated.
 */

/**
 * index.js
 */

import {
  // will be removed
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify
} from './core.js';
import { importKeys } from './keys.js';
import {createEncryptionCascade} from './cascade.js';
import {decryptSeq, encryptSeq} from './obsolete';

export default {
  encryptSeq, decryptSeq, // will be removed
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify,
  importKeys,
  createEncryptionCascade
};
export {
  encryptSeq, decryptSeq, // will be removed
  generateKey,
  encrypt,
  decrypt,
  sign,
  verify,
  importKeys,
  createEncryptionCascade
};