package io.moatwel.crypto.eddsa.ed25519.ctx;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed25519.Ed25519PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Signer;
import io.moatwel.util.ByteUtils;

import java.security.SecureRandom;

public class Ed25519ctxSchemeProvider extends SchemeProvider {

    private final HashAlgorithm algorithm;

    public Ed25519ctxSchemeProvider(HashAlgorithm algorithm) {
        super(Curve25519.getInstance());

        if (algorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
        this.algorithm = algorithm;
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed25519Signer(algorithm, this);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed25519PublicKeyDelegate(algorithm);
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
        String sigPrefix = "SigEd25519 no Ed25519 collisions";
        return ByteUtils.join(
                sigPrefix.getBytes(),
                // 0 is a flag for Ed25519ctx
                new byte[]{(byte) 0},
                new byte[]{(byte) context.length},
                context);
    }
}
