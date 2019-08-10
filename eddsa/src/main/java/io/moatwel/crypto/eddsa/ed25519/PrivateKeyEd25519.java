package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PrivateKeyEd25519 extends PrivateKey {

    private PrivateKeyEd25519(byte[] value) {
        super(value);
        if (value.length != 32) {
            throw new IllegalArgumentException("PrivateKey on ed25519 curve must have 32 byte length");
        }
    }

    public static PrivateKey fromHexString(String hexString) {
        return new PrivateKeyEd25519(HexEncoder.getBytes(hexString));
    }

    public static PrivateKey fromBytes(byte[] bytes) {
        return new PrivateKeyEd25519(bytes);
    }

    public static PrivateKey random() {
        byte[] seed = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        return new PrivateKeyEd25519(seed);
    }

    @Override
    public BigInteger getScalarSeed(HashAlgorithm algorithm) {
        byte[] hashResult = Hashes.hash(algorithm, value);
        byte[] first32 = ByteUtils.split(hashResult, 32)[0];

        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        byte[] a = ByteUtils.reverse(first32);
        return new BigInteger(a);
    }
}
