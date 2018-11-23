package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.PrivateKey;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public abstract class SchemeProvider {

    private Curve curve;

    protected SchemeProvider(Curve curve) {
        if (curve == null) {
            throw new NullPointerException("Curve must not be null");
        }
        this.curve = curve;
    }

    public Curve getCurve() {
        return curve;
    }

    public abstract EdDsaSigner getSigner();

    public abstract PublicKeyDelegate getPublicKeyDelegate();

    public abstract PrivateKey generatePrivateKey();

    public abstract byte[] dom(byte[] context);
}
