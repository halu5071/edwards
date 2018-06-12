package io.moatwel.crypto;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.Arrays;

import io.moatwel.util.HexEncoder;

public class PrivateKey {

    private final byte[] value;

    public PrivateKey(String hexString) {
        this(new BigInteger(1, HexEncoder.getBytes(hexString)));
    }

    public PrivateKey(BigInteger integer) {
        this(integer.toByteArray());
    }

    public PrivateKey(byte[] value) {
        this.value = value;
    }

    public byte[] getRaw() {
        return value;
    }

    public String getHexString() {
        return Hex.encodeHexString(this.value);
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
