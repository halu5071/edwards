package io.moatwel.crypto.eddsa.ed25519;

import java.security.SecureRandom;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.CurveProvider;
import io.moatwel.crypto.eddsa.EdKeyAnalyzer;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed25519CurveProvider extends CurveProvider {

    private HashAlgorithm hashAlgorithm;

    public Ed25519CurveProvider(HashAlgorithm algorithm) {
        super(Ed25519Curve.getCurve());

        if (algorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
        this.hashAlgorithm = algorithm;
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed25519Signer(hashAlgorithm);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed25519PublicKeyDelegate(hashAlgorithm);
    }

    @Override
    protected KeyPair generateKeyPair(KeyGenerator generator, EdKeyAnalyzer analyzer) {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[32];
        random.nextBytes(seed);

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(seed);

        return new KeyPair(privateKey, generator, analyzer);
    }
}
