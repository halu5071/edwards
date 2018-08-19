package io.moatwel.crypto;

import java.math.BigInteger;
import java.util.Arrays;

import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import io.moatwel.crypto.eddsa.ed448.PrivateKeyEd448;
import io.moatwel.util.HexEncoder;

/**
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 */
public abstract class PrivateKey {

    protected byte[] value;

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
        return this.value.equals(privateKey.value);
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
}
