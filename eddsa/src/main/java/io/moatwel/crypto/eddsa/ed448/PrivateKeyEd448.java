package io.moatwel.crypto.eddsa.ed448;

import java.security.SecureRandom;

import io.moatwel.crypto.PrivateKey;

public class PrivateKeyEd448 extends PrivateKey {

    private PrivateKeyEd448(byte[] value) {
        if (value.length != 57) {
            throw new IllegalArgumentException("PrivateKey on Ed448 curve must have 57 byte length.");
        }
        this.value = value;
    }

    @Override
    public PrivateKey random() {
        byte[] seed = new byte[57];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        return new PrivateKeyEd448(seed);
    }

    public static PrivateKey fromBytes(byte[] value) {
        return new PrivateKeyEd448(value);
    }
}
