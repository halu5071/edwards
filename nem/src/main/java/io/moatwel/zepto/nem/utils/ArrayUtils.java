package io.moatwel.zepto.nem.utils;

import java.math.BigInteger;

public class ArrayUtils {

    public static byte[][] split(byte[] bytes, int splitIndex) {
        if (splitIndex < 0 || bytes.length < splitIndex) {
            throw new IllegalArgumentException("split index is out of range");
        }

        final byte[] lhs = new byte[splitIndex];
        final byte[] rhs = new byte[bytes.length - splitIndex];

        System.arraycopy(bytes, 0, lhs, 0, lhs.length);
        System.arraycopy(bytes, splitIndex, rhs, 0, rhs.length);
        return new byte[][]{lhs, rhs};
    }

    public static BigInteger toBigInteger(final byte[] bytes) {
        final byte[] bigEndianBytes = new byte[bytes.length + 1];
        for (int i = 0; i < bytes.length; ++i) {
            bigEndianBytes[i + 1] = bytes[bytes.length - i - 1];
        }

        return new BigInteger(bigEndianBytes);
    }
}
