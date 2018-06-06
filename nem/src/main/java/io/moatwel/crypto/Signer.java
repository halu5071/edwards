package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EdCryptoProvider;

public class Signer implements DsaSigner{
    private final DsaSigner signer;

    public Signer(final KeyPair keyPair, Curve curve) {
        this(keyPair, new EdCryptoProvider(curve));
    }

    public Signer(final KeyPair keyPair, final CryptoProvider engine) {
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
