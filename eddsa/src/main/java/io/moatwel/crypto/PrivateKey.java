package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import io.moatwel.crypto.eddsa.ed448.PrivateKeyEd448;
import io.moatwel.util.HexEncoder;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * PrivateKey on Edwards-curve DSA.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class PrivateKey {

    protected final byte[] value;

    protected PrivateKey(byte[] value) {
        this.value = value;
    }

    public static PrivateKey newInstance(byte[] seed) {
        switch (seed.length) {
            case 32:
                return PrivateKeyEd25519.fromBytes(seed);
            case 57:
                return PrivateKeyEd448.fromBytes(seed);
            default:
                throw new IllegalArgumentException("PrivateKey byte length " + seed.length + " is not supported.");
        }
    }

    public static PrivateKey newInstance(String hexString) {
        return newInstance(HexEncoder.getBytes(hexString));
    }

    public abstract BigInteger getScalarSeed(HashAlgorithm algorithm);

    public byte[] getRaw() {
        return value;
    }

    public BigInteger getInteger() {
        return new BigInteger(1, value);
    }

    public String getHexString() {
        return HexEncoder.getString(this.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.value);
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PrivateKey)) {
            return false;
        }
        final PrivateKey privateKey = ((PrivateKey) obj);
        return Arrays.equals(this.value, privateKey.value);
    }
}
