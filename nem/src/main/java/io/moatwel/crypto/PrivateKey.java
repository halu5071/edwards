package io.moatwel.crypto;

import java.math.BigInteger;

import io.moatwel.util.HexEncoder;

public class PrivateKey {

    private final BigInteger value;

    public PrivateKey(final BigInteger value) {
        this.value = value;
    }

    public BigInteger getRaw() {
        return value;
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PrivateKey)) {
            return false;
        }
        final PrivateKey privateKey = ((PrivateKey) obj);
        return this.value.equals(privateKey.value);
    }

    public static PrivateKey fromHexString(final String hex) {
        try {
            return new PrivateKey(new BigInteger(1, HexEncoder.getBytes(hex)));
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e);
        }
    }

    public static PrivateKey fromBytes(byte[] bytes) {
        try {
            return new PrivateKey(new BigInteger(1, bytes));
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e);
        }
    }

    public static PrivateKey fromDecimalString(String decimal) {
        try {
            return new PrivateKey(new BigInteger(decimal, 10));
        } catch (NumberFormatException e) {
            throw new CryptoException(e);
        }
    }
}
