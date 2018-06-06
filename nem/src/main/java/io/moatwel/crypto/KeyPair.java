package io.moatwel.crypto;

public class KeyPair {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public KeyPair(PrivateKey privateKey, CryptoProvider engine) {
        this(privateKey, engine.createKeyGenerator().derivePublicKey(privateKey), engine);
    }

    public KeyPair(PrivateKey privateKey, PublicKey publicKey, CryptoProvider engine) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        if (!engine.createKeyAnalyzer().isKeyCompressed(publicKey)) {
            throw new IllegalArgumentException("Public key must be in compressed form");
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
