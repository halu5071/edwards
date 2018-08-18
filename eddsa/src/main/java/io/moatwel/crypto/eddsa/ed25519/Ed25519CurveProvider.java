package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.CurveProvider;
import io.moatwel.crypto.eddsa.EdKeyAnalyzer;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

import java.security.SecureRandom;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed25519CurveProvider extends CurveProvider {

    private HashAlgorithm hashAlgorithm;

    public Ed25519CurveProvider(HashAlgorithm algorithm) {
        super(Curve25519.getInstance());

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
        PrivateKey privateKey = PrivateKeyEd25519.random();
        return new KeyPair(privateKey, generator, analyzer);
    }
}
