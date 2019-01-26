package io.moatwel.crypto.eddsa.ed25519;

import java.security.SecureRandom;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.SchemeProvider;

/**
 * SchemeProvider for Ed25519
 *
 * @author halu5071 (Yasunori Horii)
 */
public class Ed25519SchemeProvider extends SchemeProvider {

    private final HashAlgorithm hashAlgorithm;

    public Ed25519SchemeProvider(HashAlgorithm algorithm) {
        super(Curve25519.getInstance());

        if (algorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
        this.hashAlgorithm = algorithm;
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed25519Signer(hashAlgorithm, this);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed25519PublicKeyDelegate(hashAlgorithm);
    }

    @Override
    public PrivateKey generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        return PrivateKey.newInstance(seed);
    }

    @Override
    public byte[] preHash(byte[] input) {
        return input;
    }

    @Override
    public byte[] dom(byte[] context) {
        return "".getBytes();
    }
}
