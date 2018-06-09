package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;

public class Ed25519Signer implements DsaSigner {
    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        return null;
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
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
