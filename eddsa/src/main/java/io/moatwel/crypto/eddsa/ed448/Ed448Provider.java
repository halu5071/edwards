package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.Provider;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed448Provider extends Provider {

    private HashAlgorithm hashAlgorithm;

    public Ed448Provider(HashAlgorithm hashAlgorithm) {
        super(Ed448Curve.getCurve());
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    protected EdDsaSigner getSigner() {
        return new Ed448Signer();
    }

    @Override
    protected PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed448PublicKeyDelegate(hashAlgorithm);
    }
}
