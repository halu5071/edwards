package io.moatwel.crypto.eddsa;

import java.security.SecureRandom;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/2
 */
public class EdDsaKeyGenerator implements KeyGenerator {

    private final SecureRandom random;
    private EdKeyAnalyzer analyzer;
    private Curve curve;
    private CurveProvider curveProvider;

    public EdDsaKeyGenerator(CurveProvider curveProvider) {
        this.curveProvider = curveProvider;
        this.random = new SecureRandom();
        this.curve = curveProvider.getCurve();
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

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(seed);

        return new KeyPair(privateKey, this, analyzer);
    }

    @Override
    public KeyPair generateKeyPair(PrivateKey privateKey) {
        PublicKey publicKey = derivePublicKey(privateKey);
        return new KeyPair(privateKey, publicKey, analyzer);
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        PublicKeyDelegate delegate = curveProvider.getPublicKeyDelegate();

        byte[] publicKeySeed = delegate.generatePublicKeySeed(privateKey);

        return new PublicKey(publicKeySeed);
    }
}
