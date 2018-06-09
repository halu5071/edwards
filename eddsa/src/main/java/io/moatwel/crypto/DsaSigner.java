package io.moatwel.crypto;

public interface DsaSigner {

    Signature sign(KeyPair keyPair, final byte[] data);

    boolean verify(KeyPair keyPair, final byte[] data, final Signature signature);

    boolean isCanonicalSignature(final Signature signature);

    Signature makeSignatureCanonical(final Signature signature);
}
