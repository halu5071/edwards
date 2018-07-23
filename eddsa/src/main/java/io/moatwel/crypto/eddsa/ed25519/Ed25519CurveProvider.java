package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashProvider;
import io.moatwel.crypto.eddsa.CurveProvider;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed25519CurveProvider extends CurveProvider {

    private HashProvider hashProvider;

    public Ed25519CurveProvider(HashProvider provider) {
        super(Ed25519Curve.getCurve());

        if (provider == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
        this.hashProvider = provider;
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed25519Signer(hashProvider);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed25519PublicKeyDelegate(hashProvider);
    }
}
