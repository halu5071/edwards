package io.moatwel.crypto.eddsa.ed25519.ph;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;

public class Ed25519phSchemeProvider extends SchemeProvider {

    private final HashAlgorithm algorithm;

    Ed25519phSchemeProvider(HashAlgorithm algorithm) {
        super(Curve25519.getInstance());

        if (algorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
        this.algorithm = algorithm;
    }

    @Override
    public EdDsaSigner getSigner() {
        return null;
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return null;
    }

    @Override
    public PrivateKey generatePrivateKey() {
        return null;
    }

    @Override
    public byte[] ph(byte[] input) {
        return new byte[0];
    }

    @Override
    public byte[] dom(byte[] context) {
        return new byte[0];
    }
}
