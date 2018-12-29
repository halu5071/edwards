package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.PublicKey;

/**
 * @author halu5071 (Yasunori Horii)
 */
public class EdKeyAnalyzer {

    private final Curve curve;

    EdKeyAnalyzer(Curve curve) {
        if (curve == null) {
            throw new IllegalArgumentException("Curve must not be null.");
        }
        this.curve = curve;
    }

    public boolean isKeyCompressed(PublicKey publicKey) {
        return publicKey.getRaw().length == curve.getPublicKeyByteLength();
    }
}
