package io.moatwel.crypto.eddsa.ed25519.nem;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Ed25519SchemeProvider;

public class NemV2SchemeProvider extends Ed25519SchemeProvider {

    public NemV2SchemeProvider() {
        super(HashAlgorithm.KECCAK_256);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new NemV2PublicKeyDelegate();
    }
}
