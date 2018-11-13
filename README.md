Cascade - Encryption and signing library for x-brid encryption via several cryptographic suites.
--
[![CircleCI](https://circleci.com/gh/junkurihara/cascade.svg?style=svg)](https://circleci.com/gh/junkurihara/cascade)

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
    * RSA-PSS signature [^1]
    * RSASSA-PKCS1-v1_5 signature
    * ECDSA signature
* Key generation:
  * OpenPGP
    * Public and private key pair generation w/ and w/o passphrase in OpenPGP armored format (ECC and RSA)
    * Session key generation
  * js-crypto-utils
    * Public and private key pair generation w/ and w/o passphrase in PEM armored format (ECC and RSA)
    * Session key generation
  
[^1]: RSA-PSS may not work in IE11 and Edge.

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