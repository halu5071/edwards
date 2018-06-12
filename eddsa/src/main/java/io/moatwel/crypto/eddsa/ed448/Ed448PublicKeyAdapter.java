package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyAdapter;

public class Ed448PublicKeyAdapter implements PublicKeyAdapter {

    private Ed448Curve curve;

    public Ed448PublicKeyAdapter(Ed448Curve curve) {
        this.curve = curve;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        return new byte[0];
    }
}
