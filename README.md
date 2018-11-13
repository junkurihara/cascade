Cascade - Encryption and signing library for x-brid encryption via several cryptographic suites.
--
[![CircleCI](https://circleci.com/gh/junkurihara/cascade.svg?style=svg)](https://circleci.com/gh/junkurihara/cascade)
[![npm version](https://badge.fury.io/js/crypto-cascade.svg)](https://badge.fury.io/js/crypto-cascade)

> **WARNING**: At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.

# Introduction and Overview

# Supported Crypto Suites

This library currently supports two cryptographic suites, OpenPGP and js-crypto-utils. We adopted [openpgpjs](https://openpgpjs.org/) as an implementation of OpenPGP. On the other hand, [js-crypto-utils](https://github.com/junkurihara/jscu) is a simple crypto suite for plain implementations of cryptographic functions unlike fully-specified suites like OpenPGP. We should note that js-crypto-utils can be viewed as a integrated wrapper or interfaces of RFC standardized functions that are mostly built-in ones of browsers and Node.js.

* Encryption and decryption:
  * OpenPGP
    * Public key encryption (Elliptic curve cryptography)
    * Public key encryption (RSA)
    * Session key encryption (AES-EAX)
  * js-crypto-utils
    * Public key encryption (ECDH, HKDF and AES256-GCM combination)
    * Public key encryption (RSA-OAEP)
    * Session key encryption (AES-GCM)
* Signing and verification:
  * OpenPGP
    * RSA signature
    * ECDSA signature
  * js-crypto-utils
    * RSA-PSS signature (May not work in IE11 and Edge.)
    * RSASSA-PKCS1-v1_5 signature
    * ECDSA signature
* Key generation:
  * OpenPGP
    * Public and private key pair generation w/ and w/o passphrase in OpenPGP armored format (ECC and RSA)
    * Session key generation
  * js-crypto-utils
    * Public and private key pair generation w/ and w/o passphrase in PEM armored format (ECC and RSA)
    * Session key generation

# Installation and Setup

At your project directory, do either one of the following.

```shell
$ npm install --save crypto-cascade # from npm
$ yarn add crypto-cascade # from yarn
```

Then the package is imported as follows.

```javascript
import cascade from 'crypto-cascade'
```

# Usage

## Key generation

```javascript

```

## Basic encryption simultaneously with signing

The following example describes how to encrypt a message in `Uint8Array` (or `String`) simultaneously with sining on the plaintext given message. The API `cascade.encrypt` returns an object consisting of `message` and `signature` subobjects that are able to be serialized with `serialize()`. Serialized encrypted message objects and signature objects can be de-serialized with `cascade.importEncryptedBuffer` and `cascade.importSignatureBuffer` functions and encrypted message and signature objects are obtained. By feeding those de-serialized objects with imported decryption keys, the API `cascade.decrypt` returns a decrypted data and the result of signature verification.

```javascript
const encryptionKeys = {
  publicKeys: [ keys.publicKey.keyString ],
  privateKeyPassSets:[ { privateKey: keys.privateKey.keyString, passphrase: '' } ] // for Signing
};

const encryptionConfig = {
  encrypt: {
    suite: 'jscu',
    options: { hash: 'SHA-256', encrypt: 'AES-GCM', keyLength: 32, info: '' }
  },
  sign: {
    required: true,
    suite: 'jscu',
    options: { hash: 'SHA-256' }
  }
};

// import encryption key strings
const encryptionKeyImported = await cascade.importKeys(
  'string',
  {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
);

// encrypt
const encryptionResult = await cascade.encrypt({
  message: messageSomeHowInUint8Array,
  keys: encryptionKeyImported,
  config: encryptionConfig
});

// serialize
const serializedEncrypted = encryptionResult.message.serialized();
const serializedSignature = encryptionResult.signature.serialize();

// deserialize
const deserializedEncrypted = cascade.importEncryptedBuffer(serializedEncrypted);
const deserializedSignature = cascade.importSignatureBuffer(serializedSignature);

const decryptionKeys = {
  privateKeyPassSets:[ { privateKey: keys.privateKey.keyString, passphrase: '' } ],
  publicKeys: [ keys.publicKey.keyString ] // for verification
};

// import decryption key strings
const decryptionKeyImported = await cascade.importKeys(
  'string',
  {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
);

// decrypt and verify
const decryptionResult = await cascade.decrypt({
  data: { message: deserializedEncrypted, signature: deserializedSignature },
  keys: decryptionKeyImported
});
```


## Cascaded x-brid encryption and signing

```javascript

```

```mermaid
graph TD;
    A-->B;
    A-->C;
    B-->D;
    C-->D;
```