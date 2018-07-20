package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.Provider;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed25519Provider extends Provider {

    private HashAlgorithm hashAlgorithm;

    public Ed25519Provider(HashAlgorithm hashAlgorithm) {
        super(Ed25519Curve.getCurve());

        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
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
