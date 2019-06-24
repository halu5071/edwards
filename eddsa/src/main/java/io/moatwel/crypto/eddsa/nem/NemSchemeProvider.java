package io.moatwel.crypto.eddsa.nem;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Ed25519SchemeProvider;

public class NemSchemeProvider extends Ed25519SchemeProvider {

    public NemSchemeProvider() {
        super(HashAlgorithm.KECCAK_256);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new NemPublicKeyDelegate();
    }
}
