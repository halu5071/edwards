package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.SignerAdapter;

public class Ed448SignerAdapter implements SignerAdapter {

    private final Ed448Curve curve;

    public Ed448SignerAdapter(Ed448Curve curve) {
        this.curve = curve;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        return null;
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return false;
    }
}
