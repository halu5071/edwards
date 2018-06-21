package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

public class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private Ed448Curve curve = Ed448Curve.getCurve();

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        return new byte[0];
    }
}
