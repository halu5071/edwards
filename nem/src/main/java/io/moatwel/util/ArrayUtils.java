package io.moatwel.util;

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

    public static byte[] toByteArray(BigInteger value, int numBytes) {
        byte[] outputBytes = new byte[numBytes];
        byte[] bigIntegerBytes = value.toByteArray();

        int copyStartIndex = (0x00 == bigIntegerBytes[0]) ? 1 : 0;
        int numBytesCopy = bigIntegerBytes.length - copyStartIndex;

        if (numBytesCopy > numBytes) {
            copyStartIndex += numBytesCopy - numBytes;
            numBytesCopy = numBytes;
        }

        for (int i = 0; i < numBytesCopy; ++i) {
            outputBytes[i] = bigIntegerBytes[copyStartIndex + numBytesCopy - i - 1];
        }

        return outputBytes;
    }

    public static BigInteger toBigInteger(final byte[] bytes) {
        final byte[] bigEndianBytes = new byte[bytes.length + 1];
        for (int i = 0; i < bytes.length; ++i) {
            bigEndianBytes[i + 1] = bytes[bytes.length - i - 1];
        }

        return new BigInteger(bigEndianBytes);
    }

    public static int getBit(final byte[] h, final int i) {
        return (h[i >> 3] >> (i & 7)) & 1;
    }

    public static int isEqualConstantTime(final byte[] b, final byte[] c) { // ok
        int result = 0;
        result |= b.length - c.length;
        for (int i = 0; i < b.length; i++) {
            result |= b[i] ^ c[i];
        }

        return ByteUtils.isEqualConstantTime(result, 0);
    }
}
