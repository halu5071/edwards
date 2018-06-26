package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public abstract class Provider {

    private Curve curve;

    protected Provider(Curve curve) {
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
}
