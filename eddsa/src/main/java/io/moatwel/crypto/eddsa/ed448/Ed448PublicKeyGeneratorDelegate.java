package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyGeneratorDelegate;

public class Ed448PublicKeyGeneratorDelegate implements PublicKeyGeneratorDelegate {

    private Ed448Curve curve;

    public Ed448PublicKeyGeneratorDelegate(Ed448Curve curve) {
        this.curve = curve;
    }

    @Override
    public byte[] generatePublicKeyByteArray(PrivateKey privateKey) {
        return new byte[0];
    }
}
