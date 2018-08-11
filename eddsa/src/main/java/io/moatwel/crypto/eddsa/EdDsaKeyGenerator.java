package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/2
 */
public class EdDsaKeyGenerator implements KeyGenerator {

    private EdKeyAnalyzer analyzer;
    private CurveProvider curveProvider;

    public EdDsaKeyGenerator(CurveProvider curveProvider) {
        if (curveProvider == null) {
            throw new NullPointerException("CurveProvider must not be null.");
        }
        this.curveProvider = curveProvider;
        Curve curve = curveProvider.getCurve();
        this.analyzer = new EdKeyAnalyzer(curve);
    }

    @Override
    public EdKeyAnalyzer getKeyAnalyzer() {
        return analyzer;
    }

    @Override
    public KeyPair generateKeyPair() {
        return curveProvider.generateKeyPair(this, analyzer);
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
