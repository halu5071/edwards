package io.moatwel.crypto.eddsa.ed25519.ph;

import java.security.SecureRandom;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed25519.Ed25519PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Signer;
import io.moatwel.util.ByteUtils;

public class Ed25519phSchemeProvider extends SchemeProvider {

    private final HashAlgorithm algorithm;

    public Ed25519phSchemeProvider(HashAlgorithm algorithm) {
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
        return Hashes.hash(algorithm, input);
    }

    @Override
    public byte[] dom(byte[] context) {
        String sigPrefix = "SigEd25519 no Ed25519 collisions";
        return ByteUtils.join(
                sigPrefix.getBytes(),
                new byte[]{(byte) 1},
                new byte[]{(byte) context.length},
                context);
    }
}
