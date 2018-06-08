package io.moatwel.crypto.eddsa;

import java.security.SecureRandom;

import io.moatwel.crypto.CryptoProvider;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;

public class EdDsaKeyGenerator implements KeyGenerator {

    private final SecureRandom random;
    private Curve curve;
    private CryptoProvider provider;

    public EdDsaKeyGenerator(Curve curve, CryptoProvider provider) {
        this.random = new SecureRandom();
        this.curve = curve;
        this.provider = provider;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] seed = new byte[curve.getPublicKeyByteLength()];
        this.random.nextBytes(seed);

        PrivateKey privateKey = new PrivateKey(seed);

        return new KeyPair(privateKey, provider);
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        PublicKeyGeneratorDelegate delegate = curve.getPublicKeyGeneratorDelegate();

        byte[] publicKeySeed = delegate.generatePublicKeySeed(privateKey);

        return new PublicKey(publicKeySeed);
    }
}
