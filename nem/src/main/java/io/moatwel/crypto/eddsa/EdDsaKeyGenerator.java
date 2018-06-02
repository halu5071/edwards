package io.moatwel.crypto.eddsa;

import java.security.SecureRandom;

import io.moatwel.crypto.CryptoEngine;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.util.ArrayUtils;

public class EdDsaKeyGenerator implements KeyGenerator {

    private final SecureRandom random;
    private Curve curve;
    private CryptoEngine engine;

    public EdDsaKeyGenerator(Curve curve, CryptoEngine engine) {
        this.random = new SecureRandom();
        this.curve = curve;
        this.engine = engine;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] seed = new byte[curve.getPublicKeyByteLength()];
        this.random.nextBytes(seed);

        PrivateKey privateKey = new PrivateKey(ArrayUtils.toBigInteger(seed));

        return new KeyPair(privateKey, engine);
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        byte[] h = Hashes.sha3Hash512(privateKey.getRaw().toByteArray());

//        Point a = Point.BASE.scalarMultiply(h);
//        Coordinate pubKey = a.encode();
//        return new PublicKey(pubKey.encode().getValue());
        return null;
    }
}
