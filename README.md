Cascade - An encryption and signing library for x-brid encryption via several crypto suites.
--

# Introduction and Overview

# Installation and Setup 

# Usage

# Supported Suites
* encrypt:
  * openpgp ecc/rsa (public key)
  * openpgp aes (session key)
  * naive ecc/rsa by jscu (public key)
  * naive aes by jscu (session key)
* sign: 
  * openpgp ecdsa/rsa
  * naive ecdsa/rsa-pss by jscu
* key generation:
  * openpgp ECC/RSA key generation w/ and w/o passphrase
  * naive ecc/rsa key generation using jscu w/ and w/o passphrase
  * session key generation (random bytes generation) using jscu/openpgp
