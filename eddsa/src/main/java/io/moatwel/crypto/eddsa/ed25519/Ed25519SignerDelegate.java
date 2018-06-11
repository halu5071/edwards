package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.SignerDelegate;

public class Ed25519SignerDelegate implements SignerDelegate {

    private final Ed25519Curve curve;

    public Ed25519SignerDelegate(Ed25519Curve curve) {
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
