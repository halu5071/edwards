package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

public class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private Ed448Curve curve;

    public Ed448PublicKeyDelegate(Ed448Curve curve) {
        this.curve = curve;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        return new byte[0];
    }
}
