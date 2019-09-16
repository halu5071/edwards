package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.EdKeyAnalyzer;

public class KeyPair {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public KeyPair(PrivateKey privateKey, KeyGenerator generator, EdKeyAnalyzer analyzer) {
        this(privateKey, generator.derivePublicKey(privateKey), analyzer);
    }

    public KeyPair(PrivateKey privateKey, PublicKey publicKey, EdKeyAnalyzer analyzer) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        if (publicKey != null) {
            if (!analyzer.isKeyCompressed(publicKey)) {
                throw new IllegalArgumentException("Public key must be in compressed form");
            }
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
