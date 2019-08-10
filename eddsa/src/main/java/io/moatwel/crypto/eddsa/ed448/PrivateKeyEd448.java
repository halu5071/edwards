package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.HashDelegate;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PrivateKeyEd448 extends PrivateKey {

    private PrivateKeyEd448(byte[] value) {
        super(value);
        if (value.length != 57) {
            throw new IllegalArgumentException("PrivateKey on Ed448 curve must have 57 byte length.");
        }
    }

    public static PrivateKey random() {
        byte[] seed = new byte[57];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        return new PrivateKeyEd448(seed);
    }

    public static PrivateKey fromBytes(byte[] value) {
        return new PrivateKeyEd448(value);
    }

    @Override
    public BigInteger getScalarSeed(HashDelegate hashDelegate) {
        byte[] hashResult = hashDelegate.hashPrivateKey(this);
        byte[] first57 = ByteUtils.split(hashResult, 57)[0];

        first57[0] &= 0xFC;
        first57[56] &= 0x00;
        first57[55] |= 0x80;

        byte[] reversed = ByteUtils.reverse(first57);
        return new BigInteger(reversed);
    }
}
