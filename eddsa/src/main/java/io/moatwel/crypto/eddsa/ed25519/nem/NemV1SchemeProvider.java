package io.moatwel.crypto.eddsa.ed25519.nem;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Ed25519SchemeProvider;

public class NemV1SchemeProvider extends Ed25519SchemeProvider {

    public NemV1SchemeProvider() {
        super(HashAlgorithm.KECCAK_256);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new NemV1PublicKeyDelegate();
    }
}
