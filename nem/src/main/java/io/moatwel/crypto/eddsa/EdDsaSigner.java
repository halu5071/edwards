package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;

public class EdDsaSigner implements DsaSigner {

    private final KeyPair keyPair;

    public EdDsaSigner(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    @Override
    public Signature sign(byte[] data) {
        return null;
    }

    @Override
    public boolean verify(byte[] data, Signature signature) {
        return false;
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
