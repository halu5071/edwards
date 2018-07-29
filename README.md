# Edwards
[![CircleCI](https://circleci.com/gh/halu5071/edwards.svg?style=svg&circle-token=cbf414b02faf05868c94e788f208e115aea1650d)](https://circleci.com/gh/halu5071/edwards) [![codecov](https://codecov.io/gh/halu5071/edwards/branch/master/graph/badge.svg?token=ahNKdm6dVP)](https://codecov.io/gh/halu5071/edwards) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


Edwards is a crypto library for Edwards-curve Digital Signature Algorithm (EdDSA) written in pure Java. It makes it easy to create KeyPair, sign and verify.

## How to use

First of all, you should create `Edwards` object.

```java
HashProvider hashProvider = new DefaultProvider(HashAlgorithm.KECCAK_512);
Edwards edwards = new Edwards(new Ed25519CurveProvider(hashProvider));
```

or You want to select KECCAK-512 hash algorithm and Curve25519, just write as below.

```java
Edwards edwards = new Edwards();
```

### KeyPair generation
You can generate `KeyPair` which contains `PrivateKey` and `PublicKey`.

```java
KeyPair keyPair = edwards.generateKeyPair();
PrivateKey privateKey = keyPair.getPrivateKey();
PublicKey publicKey = keyPair.getPublicKey();
```

### PublicKey generation from existing PrivateKey
Of course you can generate `PublicKey` from existing `PrivateKey` which is represented in Hex String or byte array.

```java
PrivateKey privateKey = PrivateKey.fromHexString("4fd0a24......3415d4ef");
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
boolean isVerified = edwards.verify(keyPair, /* encrypted data represented in byte array */, signature);
```

### Built-in Hash algorithm
This library use `SpongyCastle`, so you can almost all hash algorithm. Specify hash algorithm you want like this.

```java
HashProvider hashProvider = new DefaultHashProvider(HashAlgorithm.KECCAK_512);
CurveProvider curveProvider = new Ed25519CurveProvider(hashProvider);
```

or

```java
Edwards edwards = new Edwards(HashAlgorithm.KECCAK_512);
```

other algorithm here.

- SHA512
- SHA3-512
- KECCAK-512

### Custom Hash
This library support custom hash you want. Use `HashProvider` interface which has `hash()` method.

```java
public class YourAwesomeHashProvider implement HashProvider {

    @Override
    public byte[] hash(byte[]... inputs) {
        return ...;
    }
}
```

and then use your `HashProvider` to create `Edwards` object.

```java
HashProvider hashProvider = new YourAwesomeHashProvider();
Edwards edwards = new Edwards(new Ed25519CurveProvider(hashProvider));
```

## Install
if you use gradle, you can add this library like this.

```gradle
dependencies {
    compile "io.moatwel.crypto:eddsa:0.1.0-alpha"
}
```

## How to build
Use AndroidStudio or Intellij. That's all.

## Dependencies
- FindBugs
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