package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.CurveProvider;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed448CurveProvider extends CurveProvider {

    private HashAlgorithm hashAlgorithm;

    public Ed448CurveProvider(HashAlgorithm hashAlgorithm) {
        super(Ed448Curve.getCurve());

        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
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
