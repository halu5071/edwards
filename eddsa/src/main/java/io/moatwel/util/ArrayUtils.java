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

    public static byte[] toByteArray(BigInteger value, int expectedBytesLength) {
        byte[] input = value.toByteArray();
        int byteTmpLength = input.length;

        if (byteTmpLength <= expectedBytesLength) {
            return input;
        }

        int copyStartIndex;
        byte[] result;
        if (input[0] == 0x00) {
            copyStartIndex = 1;
            result = new byte[byteTmpLength - 1];
        } else {
            copyStartIndex = 0;
            result = new byte[byteTmpLength];
        }
        int numBytesCopy = byteTmpLength - copyStartIndex;

        System.arraycopy(input, copyStartIndex, result, 0, numBytesCopy);

        return result;
    }
}
