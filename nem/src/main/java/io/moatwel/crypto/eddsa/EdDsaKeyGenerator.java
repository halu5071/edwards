package io.moatwel.crypto.eddsa;

import org.apache.commons.codec.binary.Hex;

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
    private CryptoProvider provider;

    public EdDsaKeyGenerator(Curve curve, CryptoProvider provider) {
        this.random = new SecureRandom();
        this.curve = curve;
        this.provider = provider;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] seed = new byte[curve.getPublicKeyByteLength()];
        this.random.nextBytes(seed);

        PrivateKey privateKey = new PrivateKey(ArrayUtils.toBigInteger(seed));

        return new KeyPair(privateKey, provider);
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        byte[] h = Hashes.sha3Hash512(privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] = (byte)(first32[0] & 0xF8);
        first32[31] |= 0b1000000;
        first32[31] = (byte)(first32[31] & ~(1 << 8));

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);
        byte[] aX = getACoordinate(new BigInteger(curve.getBasePoint().getX().getValue()).multiply(s));
        byte[] aY = getACoordinate(new BigInteger(curve.getBasePoint().getY().getValue()).multiply(s));

        // Step4
        byte[] reversedY = ByteUtils.reverse(aY);
        reversedY[31] = aX[31];

        return new PublicKey(reversedY);
    }

    private byte[] getACoordinate(BigInteger integer) {
        return integer.mod(curve.getPrimePowerP()).toByteArray();
    }
}
