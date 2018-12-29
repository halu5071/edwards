package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.PrivateKey;

/**
 * Provide scheme used for creating public key, singing, verifying.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class SchemeProvider {

    private final Curve curve;

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
