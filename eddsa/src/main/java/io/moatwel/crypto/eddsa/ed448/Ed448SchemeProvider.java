package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.crypto.eddsa.EdKeyAnalyzer;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed448SchemeProvider extends SchemeProvider {

    private HashAlgorithm hashAlgorithm;

    public Ed448SchemeProvider(HashAlgorithm hashAlgorithm) {
        super(Curve448.getInstance());

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

    @Override
    protected KeyPair generateKeyPair(KeyGenerator generator, EdKeyAnalyzer analyzer) {
        PrivateKey privateKey = PrivateKeyEd448.random();
        return new KeyPair(privateKey, generator, analyzer);
    }
}
