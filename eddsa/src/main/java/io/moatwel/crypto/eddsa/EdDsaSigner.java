package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;

public class EdDsaSigner implements DsaSigner {

    private final Curve curve;

    public EdDsaSigner(Curve curve) {
        this.curve = curve;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        return curve.getSignerDelegate().sign(keyPair, data);
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return curve.getSignerDelegate().verify(keyPair, data, signature);
    }

    @Override
    public boolean isCanonicalSignature(Signature signature) {
        return false;
    }

    @Override
    public Signature makeSignatureCanonical(Signature signature) {
        return null;
    }
}
