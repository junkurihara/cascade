Cascade - Encryption and signing library for x-brid encryption via several cryptographic suites.
--
[![npm version](https://badge.fury.io/js/crypto-cascade.svg)](https://badge.fury.io/js/crypto-cascade)
[![CircleCI](https://circleci.com/gh/junkurihara/cascade.svg?style=svg)](https://circleci.com/gh/junkurihara/cascade)
[![Coverage Status](https://coveralls.io/repos/github/junkurihara/cascade/badge.svg?branch=develop)](https://coveralls.io/github/junkurihara/cascade?branch=develop)
[![Dependencies](https://david-dm.org/junkurihara/cascade.svg)](https://david-dm.org/junkurihara/cascade)
[![Maintainability](https://api.codeclimate.com/v1/badges/ebead374220cd81a02b9/maintainability)](https://codeclimate.com/github/junkurihara/cascade/maintainability)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **WARNING**: At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.

# Introduction and Overview

Considering existing cryptographic libraries and native APIs for JavaScript, as far as we know, fundamental implementations of primitives have been developed separately in multiple environments such as Node.js and various browsers. In order to fill gaps among those different environments, there exist several nice *universal* cryptographic suites that flawlessly work in most of modern JavaScript environments. Here we have defined 'suites' as ones providing encryption, singing and other supplemental functions like OpenPGP library.

However, they are still too primitive to realize a bit more modern cryptographic services in JavaScript. In other words, we see that simple encryption and signing provided by those primitives are insufficient to directly satisfy more complex demands, e.g., *revocation of decryption rights* after encryption of data. Considering such situation, the aim of this project called `Cascade` is to provide a flexible cryptographic application library in JavaScript that realizes the **x-brid encryption** and signing by utilizing multiple cryptographic suites. This enables us to, for instance, realize complex structures of access rights to encrypted data, e.g., revocation after encryption as mentioned above.

## X-brid Encryption

Here we shall explain the detailed mechanism of x-brid encryption by illustrating the simplest example instance of **hybrid** encryption, i.e., `x = 2`, which is a well-known cryptosystem in the current security technology. The following is a schematic block diagram of the hybrid encryption.

![Schematic Diagram of Hybrid Encryption](https://github.com/junkurihara/cascade/blob/develop/docs/assets/images/hybrid.svg?raw=true)

As we see, this hybrid procedure consists of two steps where the step 1 encrypts the given plaintext message under (one-time) session key in a certain symmetric key encryption, and the step 2 encrypts the previously-used session key under a given public key(s) as a plaintext in a public key encryption. Although this looks somewhat redundant and waste of computing resource, **it has a great advantage in terms of storage usage in the case where we have multiple receivers**, i.e., multiple public keys. Namely, the encrypted message body that is likely big would be common and recycled to all the receivers, and only encrypted session key that should be small is 'personalized' to each receivers.

Moreover, this cryptosystem could yield another merit, which is the revocation after encryption of data. Assume that we first provide receivers the encrypted message body, and recall that at this point, no one can decrypt it. This implies that you can provide 'personalized' encrypted session keys to only authorized person later and freely discard the encrypted session keys, i.e., granting and revoking decryption rights and access rights to the data. We may know that this is a very basic and fundamental concept of *encryption-based access control* that is likely to be a part of well-known digital rights management (DRM).

`Cascade` project can instantiate the above mentioned hybrid encryption by its nature, and it also generalizes this basic 2-step cryptosystem to `x`-step one (`x > 0`), namely, x-brid encryption.

## Cryptographic Functions Employed in X-brid Encryption and Future Extension

We briefly explained our concept of x-brid encryption by providing a fairly simple hybrid instance as above. As a natural consequence of the generalization by `Cascade`, we can simply increase the value `x` and compose, say, *tri-brid* (`x = 3`) or *tetra-brid* (`x = 4`) encryption by cascading symmetric encryption steps. (We are honestly unsure this technically sounds at this point, but such structures may fit a certain type of application like the relationship of hybrid encryption and DRM.)

On the other hand, there is another room to generalize the cryptosystem from the viewpoint of *encryption function* at each step of x-brid encryption. The current implementation of `Cascade` can utilize encryption functions of a couple of cryptographic suites, and they supports only basic public key encryption (RSA and elliptic curve cryptosystems) and symmetric key encryption (AES). We mean that as additions to the public/private key pair based cryptosystem, we should plan to supports other types of modern cryptography as suites. In fact, the concept and current implementation can accept more interesting and modern cryptographic primitive functions as a step of x-brid encryption. For instance:

- Broadcast encryption
- Attribute-based encryption
- Secret sharing (e.g., split our session key at the final step!)

We can see that by employing those functions at some steps, new types of cryptographic application could be realized.

We also mention that a classical broadcast encryption based on tree can be possibly instantiated in the context of x-brid encryption. This is from the following observation. First consider to attach public key encryption to all steps, and assume that the plaintext message at each step is the private key used in the previous step. This composes a tree of multiple layers of private key encapsulation that is the core of tree-based broadcast encryption.

# Supported Crypto Suites

This library currently supports two cryptographic suites, OpenPGP and js-crypto-utils. We adopted [openpgpjs](https://openpgpjs.org/) as an implementation of OpenPGP. On the other hand, [js-crypto-utils](https://github.com/junkurihara/jscu) is a simple crypto suite for plain implementations of cryptographic functions unlike fully-specified suites like OpenPGP. We should note that js-crypto-utils can be viewed as a integrated wrapper or interfaces of RFC standardized functions that are mostly built-in ones of browsers and Node.js.

* Encryption and decryption:
  * js-crypto-utils
    * Public key encryption (ECDH, HKDF and AES256-GCM combination)
    * Public key encryption (RSA-OAEP)
    * Session key encryption (AES-GCM)
  * OpenPGP
    * Public key encryption (Elliptic curve cryptography)
    * Public key encryption (RSA)
    * Session key encryption (AES-EAX)
* Signing and verification:
  * js-crypto-utils
    * RSA-PSS signature (May not work in IE11 and Edge.)
    * RSASSA-PKCS1-v1_5 signature
    * ECDSA signature
  * OpenPGP
    * RSA signature
    * ECDSA signature
* Key generation:
  * js-crypto-utils
    * Public and private key pair generation w/ and w/o passphrase in PEM armored format (ECC and RSA)
    * Session key generation
  * OpenPGP
    * Public and private key pair generation w/ and w/o passphrase in OpenPGP armored format (ECC and RSA)
    * Session key generation

# Installation and Setup

## Installation

At your project directory, first do either one of the following.

```shell
$ npm install --save crypto-cascade # from npm
$ yarn add crypto-cascade # from yarn
```

Then import the `Cascade` library as follows.

```javascript
import cascade from 'crypto-cascade'
```

Of cource, you can also directly import the source code by cloning this Github repo.

## Finishing up the setup

The `Cascade` library doesn't internally import cryptographic suites, i.e., `js-crypto-utils` and `openpgpjs` in a static manner, but it loads them in a dynamic manner. In particular, it calls those suites via `require` for `Node.js` and as `window` objects for browsers. This means that **for browsers, both of or either one of `js-crypto-utils` (`jscu.bundle.js`) and `openpgpjs` (`openpgp.js`/`openpgp.min.js`) must be pre-loaded by `<script>` tags in html files**. Also we should note that for `openpgpjs`, the webworker file `openpgp.worker.js`/`openpgp.worker.min.js` is required to be located in the directory where the `openpgp.js`/`openpgp.min.js` exists. For browsers, the default path to `openpgp.worker.js`/`openpgp.worker.min.js` is the root of your url path, and you can change it by directly specifying the location as follows.

```javascript
import cascade from 'crypto-cascade';
cascade.config.openpgp.workerPathWeb = 'path/to/openpgp.worker.min.js';
```

# Usage

Here we give some basic example of usecases of `Cascade`. This section is organized as follows. First, we explain how to generate keys in `Cascade`. Then as a function employed at each step of x-brid encryption, we describe a very basic *single* encryption and signing operations in `Cascade`. This can be also viewed as the case where `x = 1`. After these warmp-ups, we finally show how to employ the x-brid encryption in `Cascade`. We should really note that this is just an example and the source/test codes and JSDoc is useful to understand the detailed mechanism and usage of `Cascade`.

## Key generation

`Cascade` provides a basic function to generate PEM-formatted and OpenPGP-armored public private key pairs. The following example describes an example to generate PEM-formatted public and private keys of elliptic curve cryptography using `js-crypto-utils`.

```javascript
const keyParam = {
  suite: 'jscu', // use 'js-crypto-utils'
  keyParams: { type: 'ec', curve: 'P-256' }
};
const keyPair = await cascade.generateKey(keyParam);
const publicKeyPEM = keyPair.publicKey.keyString; // EC public key in PEM format
const privateKeyPEM = keyPair.privateKey.keyString; // EC private key in PEM format
```

Here we should note that for the key generation using `js-crypto-utils`, the generated public key is encoded as `SubjectPublicKeyInfo` specified as a part of X.509 public key certificate ([RFC5280](https://tools.ietf.org/html/rfc5280)). On the other hand, the generated private key is encoded as `PrivateKeyInfo`/`OneAsymmetricKey` defined in PKCS#8 ([RFC5958](https://tools.ietf.org/html/rfc5958)). Hence the private key can be encrypted with a passphrase just by passing API the passphrase string as given below.

```javascript
const keyParam = {
  suite: 'jscu',
  keyParams: { type: 'ec', curve: 'P-256' },
  passphrase: 'secret passphrase'
};
const keyPair = await cascade.generateKey(keyParam);
```

Then, the protected private key is encoded as `EncryptedPrivateKeyInfo`.

Note that in addition to `jscu` as `keyParam.suite`, `openpgp` is also available. The key generation API can generate not only EC public and private key strings but also RSA ones and session keys, where generated session keys are just random bytes given in `Uint8Array` unlike formatted strings of public and private keys.

## Basic encryption simultaneously with signing

The following example describes how to simply encrypt a message in `Uint8Array` (`String` is also accepted) simultaneously with signing on the given plaintext message in `Cascade`. Since the cascaded encryption, i.e., x-brid encryption, will be employed by chaining this basic encryption and decryption function, we shall firstly explain this basic function and its usage in a step-by-step manner.

First of all, we need to import keys to be used, and obtain `Keys` object that will be used to encrypt and decrypt in `Cascade`.

```javascript
const encryptionKeys = {
  publicKeys: [ keys.publicKey.keyString ],
  privateKeyPassSets:[ { privateKey: keys.privateKey.keyString, passphrase: '' } ] // for Signing
};

// import encryption key strings
const encryptionKeyImported = await cascade.importKeys(
  'string',
  {keys: encryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['encrypt', 'sign']}
);
```

The configuration object for encryption is also required like the following form that must be matched with the type of given encryption and signing keys imported. The following is an example for the case where the given public and private keys are PEM-formatted EC keys, i.e., ECDH+HKDF public key encryption and ECDSA signing, via `js-crypto-utils` (as referred to as `jscu` in the code block).

```javascript
// Encryption and signing configuration
const encryptionConfig = {
  encrypt: {
    suite: 'jscu',
    options: {
      // HKDF with SHA-256 is employed on the master secret derived from ECDH.
      hash: 'SHA-256',
      info: '',
      keyLength: 32,
      // The session key HKDF derives is used to encrypt the message via AES-GCM.
      encrypt: 'AES-GCM'
    }
  },
  sign: {
    suite: 'jscu',
    // Signature is required and computed simultaneously with encryption.
    required: true,
    options: {
      hash: 'SHA-256'
    }
  }
};
```

With the imported encryption/signing keys and encryption config, the encryption API `cascade.encrypt` employs a single-phase encryption with signing, and it returns an object consisting of `message` and `signature` sub-objects. Those sub-objects are able to be respectively serialized with their instance method `serialize()`.

```javascript
// encrypt
const encryptionResult = await cascade.encrypt({
  message: messageSomeHow, // in Uint8Array or String
  keys: encryptionKeyImported,
  config: encryptionConfig
});

// serialize
const serializedEncrypted = encryptionResult.message.serialize();
const serializedSignature = encryptionResult.signature.serialize();
```

Serialized objects must be de-serialized, i.e., ones in object forms, for decryption in `Cascade`. Serialized encrypted message objects and signature objects can be de-serialized with `cascade.importEncryptedBuffer` and `cascade.importSignatureBuffer` functions and encrypted message and signature objects are obtained.

```javascript
// de-serialize
const deserializedEncrypted = cascade.importEncryptedBuffer(serializedEncrypted);
const deserializedSignature = cascade.importSignatureBuffer(serializedSignature);
```

 Much like basic encryption, the decryption and verification key strings must be imported and the `Keys` object is required to decrypt de-serialized message objects.

```javascript
const decryptionKeys = {
  privateKeyPassSets:[ { privateKey: keys.privateKey.keyString, passphrase: '' } ],
  publicKeys: [ keys.publicKey.keyString ] // for verification
};

// import decryption key strings
const decryptionKeyImported = await cascade.importKeys(
  'string',
  {keys: decryptionKeys, suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'}, mode: ['decrypt', 'verify']}
);
```

 By putting de-serialized message and signature objects with imported decryption keys as given above, the `Cascade` API `cascade.decrypt` returns a decrypted data and the result of signature verification.

```javascript
// decrypt and verify
const decryptionResult = await cascade.decrypt({
  data: { message: deserializedEncrypted, signature: deserializedSignature },
  keys: decryptionKeyImported
});
```

That's all the *basic* encryption and decryption steps, and the cascaded encryption/decryption in `Cascade` are composed of multiple basic ones that chained sequentially. Next section will briefly explain this step with some exemplary operations.

## Cascaded x-brid encryption with signing

Here we describe how to employ cascaded x-brid encryption simultaneously with signing by showing a simple example.

All we need to prepare for the cascaded x-brid encryption/decryption is exactly similar to the basic encryption described in the previous section. One main difference from basic ones is that we have to define an **encryption procedure** given as an array of encryption configuration objects. The following is an sample encryption procedure that will be used in this section.

```javascript
const encryptionProcedure = [
  { // step 1
    encrypt: {
      suite: 'jscu',
      onetimeKey: {keyParams: {type: 'session', length: 32}}, options: {name: 'AES-GCM'}
    },
    sign: { required: true }
  },
  { // step 2
    encrypt: {
      suite: 'jscu', options: { hash: 'SHA-256', info: '', keyLength: 32, encrypt: 'AES-GCM' }
    },
    sign: { suite: 'jscu', required: true, options: { hash: 'SHA-256' } }
  }
];
```

The above example describes a procedure of **hybrid encryption** where the given message is first encrypted under a one-time session key generated internally at `Cascade` (step 1), and the session key is then encrypted under the externally given public key (step 2). We can see that the `encrypt.onetimeKey` specifies the key parameters generated at the step 1, and that the step 2 does not require the entry since public key(s) are given externally. In terms of signatures, the signing parameters and keys given the final step, i.e., step 2, will be applied all the other steps if `sign.required = true`.

After setting up an encryption procedure, we then obtain a `Keys` object by importing key strings in an exactly same manner as the basic encryption given above. This `Keys` object must be matched the parameters of the final step in the given encryption procedure. We then instantiate a `Cascade` object with the `Keys` object and the given encryption procedure.

```javascript
const encryptionKeys = {
  publicKeys: [ keys.publicKey.keyString ], // for encryption
  privateKeyPassSets: [ { privateKey: keys.privateKey.keyString, passphrase: '' } ] // for Signing
};

// import encryption keys
const encryptionKeyImported = await cascade.importKeys(
  'string',
  {
    keys: encryptionKeys,
    suite: {encrypt_decrypt: 'jscu', sign_verify: 'jscu'},
    mode: ['encrypt', 'sign']
  }
);

// instantiate encryption process
const eProcess = await cascade.createEncryptionCascade({
  keys: encryptionKeyImported,
  procedure: encryptionProcedure
});
```

Now all the encryption setup has done and we can encrypt a message in `Uint8Array` (or `string`) via `encrypt` method of the `Cascade` object. The ciphertext is given as an `EncryptedMessage` object, and the object can be viewed as an array in which each element exactly corresponds to each step of the encryption procedure. Its serialized data can be obtained through `serialize` method, and conversely, we can de-serialize the serialized data through `importCascadeBuffer` function.

```javascript
// encrypt
const encrypted = await eProcess.encrypt(message);

// serialize
const serialized = encrypted.serialize();

// de-serialize
const deserialized = cascade.importCascadedBuffer(serialized);
```

Decryption operation is exactly inverse of the above encryption operation. First we must obtain a `Keys` object by importing decryption and verification keys, and instantiate the decryption `Cascade` object to setup the decryption process by the obtained `EncryptedMessage` object. Then, the plaintext message is finally obtained through `decrypt` method.

```javascript
const decryptionKeys = {
  privateKeyPassSets:[ { privateKey: keys.privateKey.keyString, passphrase: '' } ], // for decryption
  publicKeys: [ keys.publicKey.keyString ] // for verification
};

// import decryption keys
const decryptionKeyImported = await cascade.importKeys(
  'string',
  {
    keys: decryptionKeys,
    suite: { encrypt_decrypt: 'jscu', sign_verify: 'jscu' },
    mode: ['decrypt', 'verify']
  }
);

// instantiate decryption process
const dProcess = await cascade.createDecryptionCascade({
  keys: decryptionKeyImported,
  encrypted: deserialized
});

// decrypt
const decrypted = await dProcess.decrypt();
```

## Drop and extract a part of ciphertext

We can also **drop and extract** a part of ciphertext, namely some elements of the array `EncryptedMessage`. This enables us to control access rights of users who received the ciphertext by giving them the extracted part separately.

```javascript
const idx = 0; // 0 to length-1 of encryption procedure
const extracted = encrypted.extract(idx); // drop and extract the indicated part from EncryptedMessage object

// still serializable after extraction
const serialized = encrypted.serialize();

// extracted part is an array where each element is serializable as well
const serializedExtracted = extracted.map( (obj) => obj.serialize() );

// de-serialize
const deserialized = cascade.importCascadedBuffer(serialized);

// de-serialize each extracted part.
const deserializedExtracted = cascade.importRawEncryptedBufferList(serializedExtracted);

// recover original EncryptedMessage object]
deserialized.insert(idx, deserializedExtracted);
```

# Note

At this point, limitations of `Cascade` are basically from those of [js-crypto-utils](https://github.com/junkurihara/jscu) and [openpgpjs](https://openpgpjs.org/). Please refer to their documents first.

# Lisence

Licensed under the MIT license, see `LICENSE` file.