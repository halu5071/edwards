package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.Provider;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

public class Ed448Provider extends Provider {

    private HashAlgorithm hashAlgorithm;

    public Ed448Provider(HashAlgorithm hashAlgorithm) {
        super(Ed448Curve.getCurve());
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    protected EdDsaSigner getSigner() {
        return null;
    }

    @Override
    protected PublicKeyDelegate getPublicKeyDelegate() {
        return null;
    }
}
