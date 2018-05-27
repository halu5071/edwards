package io.moatwel.zepto.nem.crypto;

public class KeyPair {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public KeyPair(PrivateKey privateKey, CryptoEngine engine) {
        this(privateKey, engine.createKeyGenerator().derivePublicKey(privateKey), engine);
    }

    public KeyPair(PrivateKey privateKey, PublicKey publicKey, CryptoEngine engine) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        if (!engine.createKeyAnalyzer().isKeyCompressed(publicKey)) {
            throw new IllegalArgumentException("Public key must be in compressed form");
        }
    }

    public static KeyPair random(CryptoEngine engine) {
        KeyPair pair = engine.createKeyGenerator().generateKeyPair();
        return new KeyPair(pair.getPrivateKey(), pair.getPublicKey(), engine);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
