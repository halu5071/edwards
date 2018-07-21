# Edwards
[![CircleCI](https://circleci.com/gh/halu5071/edwards.svg?style=svg&circle-token=cbf414b02faf05868c94e788f208e115aea1650d)](https://circleci.com/gh/halu5071/edwards) [![codecov](https://codecov.io/gh/halu5071/edwards/branch/master/graph/badge.svg?token=ahNKdm6dVP)](https://codecov.io/gh/halu5071/edwards) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


Edwards is a crypto library for Edwards-curve Digital Signature Algorithm (EdDSA) written in pure Java. It makes it easy to generate EdDsa operation (generate KeyPair, signing, verifying).

```java
Edwards edwards = new Edwards(new Ed25519Provider(HashAlgorithm.KECCAK_512));
```

## KeyPair generation
You can generate `KeyPair` which contains `PrivateKey` and `PublicKey`.

```java
KeyPair keyPair = edwards.generateKeyPair();
PrivateKey privateKey = keyPair.getPrivateKey();
PublicKey publicKey = keyPair.getPublicKey();
```

## PublicKey generation from existing PrivateKey
Of course you can generate `PublicKey` from existing `PrivateKey` which is represented in Hex String.

```java
PrivateKey privateKey = new PrivateKey("4fd0a24......3415d4ef");
PublicKey publicKey = edwards.derivePublicKey(privateKey);
```

## Signing

```java
KeyPair keyPair = ...;
Signature signature = edwards.sign(keyPair, /* data represented in byte array */);
```

## Verifying

```java
KeyPair keyPair = ...;
Signature signature = ...;
boolean isVerified = edwards.verify(keyPair, /* data represented in byte array */, signature);
```

## Dependencies
- Apache Commons Codec
- Spongy Castle

## License

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