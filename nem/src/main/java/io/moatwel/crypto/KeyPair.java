package io.moatwel.crypto;

public class KeyPair {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public KeyPair(PrivateKey privateKey, CryptoProvider provider) {
        this(privateKey, provider.createKeyGenerator().derivePublicKey(privateKey), provider);
    }

    public KeyPair(PrivateKey privateKey, PublicKey publicKey, CryptoProvider provider) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        if (!provider.createKeyAnalyzer().isKeyCompressed(publicKey)) {
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
