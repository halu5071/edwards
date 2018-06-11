# Edwards
[![CircleCI](https://circleci.com/gh/halu5071/edwards.svg?style=svg&circle-token=cbf414b02faf05868c94e788f208e115aea1650d)](https://circleci.com/gh/halu5071/edwards)

Edwards is a crypto library for Edwards-curve Digital Signature Algorithm (EdDSA) written in pure Java. It makes it easy to generate EdDsa operation (generate KeyPair, signing, verifying).

```java
Edwards edwards = new Edwards(Ed25519Curve.getCurve());
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