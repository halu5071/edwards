package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyAnalyzer;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.Curve;

public class EdKeyAnalyzer implements KeyAnalyzer {

    private Curve curve;

    public EdKeyAnalyzer(Curve curve) {
        this.curve = curve;
    }

    @Override
    public boolean isKeyCompressed(PublicKey publicKey) {
        return publicKey.getRaw().length == curve.getPublicKeyByteLength();
    }
}
