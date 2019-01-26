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

    /**
     * Return a pre-hashed byte array.
     *
     * <p>
     * check the pre-hash function of each schemes.
     *
     * @param input byte array which will be hashed.
     * @return hashed byte array
     */
    public abstract byte[] preHash(byte[] input);

    /**
     * Return byte array which the result of 'dom' operation
     * <p>
     * see <a href="https://tools.ietf.org/html/rfc8032#section-2" target="_blank">RFC8032</a>
     *
     * @param context context of signing and verifying
     * @return byte array
     */
    public abstract byte[] dom(byte[] context);
}
