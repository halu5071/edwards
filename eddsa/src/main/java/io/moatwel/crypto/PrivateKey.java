package io.moatwel.crypto;

import io.moatwel.util.HexEncoder;

import java.math.BigInteger;
import java.util.Arrays;

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
}
