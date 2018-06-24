package io.moatwel.crypto.eddsa;

import java.security.SecureRandom;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;

public class EdDsaKeyGenerator implements KeyGenerator {

    private final SecureRandom random;
    private Curve curve;
    private EdKeyAnalyzer analyzer;
    private HashAlgorithm hashAlgorithm;

    public EdDsaKeyGenerator(Curve curve) {
        this.random = new SecureRandom();
        this.curve = curve;
        this.analyzer = new EdKeyAnalyzer(curve);
    }

    @Override
    public EdKeyAnalyzer getKeyAnalyzer() {
        return analyzer;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] seed = new byte[curve.getPublicKeyByteLength()];
        this.random.nextBytes(seed);

        PrivateKey privateKey = PrivateKey.fromBytes(seed);

        return new KeyPair(privateKey, this, analyzer);
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        PublicKeyDelegate delegate = curve.getPublicKeyGeneratorDelegate();

        byte[] publicKeySeed = delegate.generatePublicKeySeed(privateKey);

        return new PublicKey(publicKeySeed);
    }
}
