package io.moatwel.zepto.nem.crypto.ed25519;

import io.moatwel.zepto.nem.crypto.DsaSigner;
import io.moatwel.zepto.nem.crypto.Signature;

public class EdDsaSigner implements DsaSigner {
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
