package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public abstract class CurveProvider {

    private Curve curve;

    protected CurveProvider(Curve curve) {
        if (curve == null) {
            throw new IllegalArgumentException("Curve must not be null");
        }
        this.curve = curve;
    }

    public Curve getCurve() {
        return curve;
    }

    protected abstract EdDsaSigner getSigner();

    protected abstract PublicKeyDelegate getPublicKeyDelegate();

    protected abstract KeyPair generateKeyPair(KeyGenerator generator, EdKeyAnalyzer analyzer);
}
