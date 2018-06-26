package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.Provider;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

public class Ed25519Provider extends Provider {

    private HashAlgorithm hashAlgorithm;

    public Ed25519Provider(HashAlgorithm hashAlgorithm) {
        super(Ed25519Curve.getCurve());
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed25519Signer();
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed25519PublicKeyDelegate(hashAlgorithm);
    }
}
