package io.moatwel.crypto.eddsa.ed448.ph;

import java.security.SecureRandom;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.crypto.eddsa.ed448.Curve448;
import io.moatwel.crypto.eddsa.ed448.Ed448PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed448.Ed448Signer;
import io.moatwel.util.ByteUtils;

public class Ed448phSchemeProvider extends SchemeProvider {

    private final HashAlgorithm algorithm;

    public Ed448phSchemeProvider(HashAlgorithm algorithm) {
        super(Curve448.getInstance());

        if (algorithm == null) {
            throw new IllegalArgumentException("argument HashAlgorithm must not be null.");
        }
        this.algorithm = algorithm;
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed448Signer(algorithm, this);
    }

    @Override
    public PublicKeyDelegate getPublicKeyDelegate() {
        return new Ed448PublicKeyDelegate(algorithm);
    }

    @Override
    public PrivateKey generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[57];
        random.nextBytes(seed);
        return PrivateKey.newInstance(seed);
    }

    @Override
    public byte[] ph(byte[] input) {
        return Hashes.hash(algorithm, 64, input);
    }

    @Override
    public byte[] dom(byte[] context) {
        String domPrefix = "SigEd448";
        return ByteUtils.join(
                domPrefix.getBytes(),
                // 1 is a flag for Ed448ph
                new byte[]{(byte) 1},
                new byte[]{(byte) context.length},
                context);
    }
}
