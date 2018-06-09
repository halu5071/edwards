package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.PublicKey;

public class EdKeyAnalyzer {

    private Curve curve;

    public EdKeyAnalyzer(Curve curve) {
        this.curve = curve;
    }

    public boolean isKeyCompressed(PublicKey publicKey) {
        return publicKey.getRaw().length == curve.getPublicKeyByteLength();
    }
}
