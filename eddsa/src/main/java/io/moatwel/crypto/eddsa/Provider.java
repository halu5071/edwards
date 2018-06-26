package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;

public abstract class Provider {

    private Curve curve;

    protected Provider(Curve curve) {
        this.curve = curve;
    }

    public Curve getCurve() {
        return curve;
    }

    protected abstract EdDsaSigner getSigner();

    protected abstract PublicKeyDelegate getPublicKeyDelegate();
}
