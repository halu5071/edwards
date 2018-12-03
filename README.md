# Edwards
[![CircleCI](https://circleci.com/gh/halu5071/edwards.svg?style=svg&circle-token=cbf414b02faf05868c94e788f208e115aea1650d)](https://circleci.com/gh/halu5071/edwards) [![codecov](https://codecov.io/gh/halu5071/edwards/branch/master/graph/badge.svg?token=ahNKdm6dVP)](https://codecov.io/gh/halu5071/edwards) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [ ![Download](https://api.bintray.com/packages/halu5071/edwards/edwards/images/download.svg) ](https://bintray.com/halu5071/edwards/edwards/_latestVersion)


Edwards is a crypto library for Edwards-curve Digital Signature Algorithm (EdDSA). It makes it easy to create KeyPair, sign and verify your message.

## How to use

First of all, you should create `Edwards` object.

```java
Edwards edwards = new Edwards(new Ed25519SchemeProvider(HashAlgorithm.SHA_512));
```

or if you select KECCAK-512 hash algorithm and Curve25519, just write as below.

```java
Edwards edwards = new Edwards();
```

### KeyPair generation
You can generate `KeyPair` which contains `PrivateKey` and `PublicKey` from `Edwards` object.

```java
KeyPair keyPair = edwards.generateKeyPair();
PrivateKey privateKey = keyPair.getPrivateKey();
PublicKey publicKey = keyPair.getPublicKey();
```

### PublicKey generation from existing PrivateKey
Of course you can generate `PublicKey` from existing `PrivateKey` which is represented in Hex String or byte array.

```java
PrivateKey privateKey = PrivateKey.newInstance("4fd0a24......3415d4ef");
PublicKey publicKey = edwards.derivePublicKey(privateKey);
```

### Signing

```java
KeyPair keyPair = ...;
Signature signature = edwards.sign(keyPair, /* data represented in byte array */);
```

### Verifying

```java
KeyPair keyPair = ...;
Signature signature = ...;
boolean isVerified = edwards.verify(keyPair, /* data represented in byte array */, signature);
```

### Built-in Hash algorithm
This library use `SpongyCastle` internally, so you can almost all hash algorithm. Specify hash algorithm you want like this.

```java
SchemeProvider schemeProvider = new Ed25519SchemeProvider(HashAlgorithm.SHA_512);
```

or

```java
Edwards edwards = new Edwards(HashAlgorithm.KECCAK_512);
```

other algorithm here.

- SHA512
- SHA3-512
- KECCAK-512
- SHAKE-256

If you want to add other hash algorithms, do not hesitate to send me request, or pull request.

## Install
A package of this software is provided from jcenter. Maven or Gradle may be useful. Just write as below.

### Gradle

```gradle
buildscript {
    repositories {
        jcenter()
    }
}

dependencies {
    compile "io.moatwel.crypto:eddsa:0.3.0-alpha"
}
```

### Maven

```xml
<dependency> 
    <groupId>io.moatwel.crypto</groupId> 
    <artifactId>eddsa</artifactId> 
    <version>0.3.0-alpha</version>
    <type>pom</type> 
</dependency>
```

## How to build
Please use AndroidStudio or Intellij. Clone this repository, and open it.


## About ed25519 implemetation of NEM
NEM(XEM), a cryptocurrency, use ed25519 algorithm to generate key pair or operate some others. However, that implementation of ed25519 is different from the reference implementation or this software. If you want to know more, see [RFC8032](https://tools.ietf.org/html/rfc8032). So you can not use this software as it is. I will show you how to use `edwards` for development NEM application.

#### 1. Fork this library
#### 2. Replace implementation
In present NEM implementation, generator of public key do hash a reversed byte array of private key. You will do that on this library like this.

```java
// Ed25519PublicKeyDelegate.java
byte[] h = Hashes.hash(hashAlgorithm, ByteUtils.reverse(privateKey.getRaw()));
```
see [this line](https://github.com/halu5071/edwards/blob/master/eddsa/src/main/java/io/moatwel/crypto/eddsa/ed25519/Ed25519PublicKeyDelegate.java#L33)

#### 3. And use KECCAK-512 hash algorithm

```java
Edwards edwards = new Edwards(HashAlgorithm.KECCAK_512);
```

FYI, NEM2 implementation about a logic of generating public key is already fixed, and they use SHA3-512 hash algorithm instead of KECCAK-512. See [here](https://github.com/nemtech/nem2-sdk-java/blob/master/src/main/java/io/nem/core/crypto/ed25519/Ed25519Utils.java#L38).

## Dependencies
This software is built on some Open Source Softwares.

- Spongy Castle

## License
This software is under the Apache License, Version 2.0.

```
Copyright 2018 halu5071 (Yasunori Horii)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
