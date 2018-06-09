package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.EdKeyAnalyzer;

public interface KeyGenerator {

    EdKeyAnalyzer getKeyAnalyzer();

    KeyPair generateKeyPair();

    PublicKey derivePublicKey(PrivateKey privateKey);
}
