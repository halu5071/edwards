# Edwards
[![CircleCI](https://circleci.com/gh/halu5071/edwards.svg?style=svg&circle-token=cbf414b02faf05868c94e788f208e115aea1650d)](https://circleci.com/gh/halu5071/edwards) [![codecov](https://codecov.io/gh/halu5071/edwards/branch/master/graph/badge.svg?token=ahNKdm6dVP)](https://codecov.io/gh/halu5071/edwards) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


Edwards is a crypto library for Edwards-curve Digital Signature Algorithm (EdDSA). This library makes it easy to create KeyPair, sign and verify your message.

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
byte[] data = ...;
Signature signature = edwards.sign(keyPair, data);
```

### Verifying

```java
PublicKey publicKey = ...;
Signature signature = ...;
byte[] data = ...;
boolean isVerified = edwards.verify(publicKey, data, signature);
```

### Built-in Scheme
Edwards supports some schemes. 

- Ed25519
- Ed25519ctx
- Ed25519ph
- Ed448
- Ed448ph

`Ed25591ctx`, `Ed25519ph` are contextualized extensions of the `Ed25519` scheme, and also `Ed448ph` is a contextualized extension of `Ed448` scheme.

In addition, `NemV1SchemeProvider` and `NemV2SchemeProvider` are implemented. The use case of this provider is some operation in NEM v1 and v2 respectively.

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
        mavenCentral()
    }
}

dependencies {
    compile "io.moatwel.crypto:eddsa:0.8.0"
}
```

### Maven

```xml
<dependency> 
    <groupId>io.moatwel.crypto</groupId> 
    <artifactId>eddsa</artifactId> 
    <version>0.8.0</version>
    <type>pom</type> 
</dependency>
```

## How to build
Please use AndroidStudio or Intellij. Clone this repository, and open it.


## Dependencies
This software is built on some Open Source Softwares.

- [Spongy Castle](https://github.com/rtyley/spongycastle)


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
