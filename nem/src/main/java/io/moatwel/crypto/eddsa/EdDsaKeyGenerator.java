package io.moatwel.crypto.eddsa;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.CryptoProvider;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

public class EdDsaKeyGenerator implements KeyGenerator {

    private final SecureRandom random;
    private Curve curve;
    private CryptoProvider engine;

    public EdDsaKeyGenerator(Curve curve, CryptoProvider engine) {
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

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] = (byte)(first32[0] & 0xF8);

        // Step3
        BigInteger a = ByteUtils.getLittleEndianInteger(first32);

        // Step4
        return null;
    }
}
