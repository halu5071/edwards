package io.moatwel.zepto.nem.crypto;

import io.moatwel.zepto.nem.crypto.ed25519.EdCryptoEngine;

public class Signer implements DsaSigner{
    private final DsaSigner signer;

    public Signer(final KeyPair keyPair) {
        this(keyPair, new EdCryptoEngine());
    }

    public Signer(final KeyPair keyPair, final CryptoEngine engine) {
        this(engine.createDsaSigner(keyPair));
    }

    public Signer(final DsaSigner signer) {
        this.signer = signer;
    }

    @Override
    public Signature sign(final byte[] data) {
        return this.signer.sign(data);
    }

    @Override
    public boolean verify(final byte[] data, final Signature signature) {
        return this.signer.verify(data, signature);
    }

    @Override
    public boolean isCanonicalSignature(final Signature signature) {
        return this.signer.isCanonicalSignature(signature);
    }

    @Override
    public Signature makeSignatureCanonical(final Signature signature) {
        return this.signer.makeSignatureCanonical(signature);
    }
}
