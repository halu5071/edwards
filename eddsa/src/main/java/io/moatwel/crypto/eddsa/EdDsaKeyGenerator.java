package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;

/**
 * @author halu5071 (Yasunori Horii)
 */
public class EdDsaKeyGenerator implements KeyGenerator {

    private final EdKeyAnalyzer analyzer;
    private final SchemeProvider schemeProvider;

    public EdDsaKeyGenerator(SchemeProvider schemeProvider) {
        if (schemeProvider == null) {
            throw new IllegalArgumentException("SchemeProvider must not be null.");
        }
        this.schemeProvider = schemeProvider;
        Curve curve = schemeProvider.getCurve();
        this.analyzer = new EdKeyAnalyzer(curve);
    }

    @Override
    public EdKeyAnalyzer getKeyAnalyzer() {
        return analyzer;
    }

    @Override
    public KeyPair generateKeyPair() {
        PrivateKey privateKey = schemeProvider.generatePrivateKey();
        return generateKeyPair(privateKey);
    }

    @Override
    public KeyPair generateKeyPair(PrivateKey privateKey) {
        PublicKey publicKey = derivePublicKey(privateKey);
        return new KeyPair(privateKey, publicKey, analyzer);
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("PrivateKey must not be null.");
        }
        PublicKeyDelegate delegate = schemeProvider.getPublicKeyDelegate();

        byte[] publicKeySeed = delegate.generatePublicKeySeed(privateKey);

        return new PublicKey(publicKeySeed);
    }
}
