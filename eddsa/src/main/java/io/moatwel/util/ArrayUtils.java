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

    public static int[] reverse(int[] input) {
        int[] output = new int[input.length];
        int counter = 0;
        for (int i : input) {
            output[input.length - counter - 1] = i;
            counter++;
        }
        return output;
    }

    public static byte[] toByteArray(BigInteger value, int expectedBytesLength) {
        byte[] input = value.toByteArray();
        int byteTmpLength = input.length;

        if (byteTmpLength <= expectedBytesLength) {
            return input;
        }

        int copyStartIndex = 0;
        byte[] result;

        if (input[0] == 0x00) {
            copyStartIndex = 1;
        }

        result = new byte[expectedBytesLength];

        System.arraycopy(input, copyStartIndex, result, 0, expectedBytesLength);

        return result;
    }

    public static int[] toBinaryArray(BigInteger integer) {
        byte[] tmp = integer.toByteArray();
        int[] array = new int[tmp.length * 8];
        for (int i = 0; i < tmp.length; i++) {
            for (int j = 0; j < 8; j++) {
                array[i * 8 + j] = (tmp[i] & 0x80) / 0x80;
                tmp[i] <<= 1;
            }
        }

        int count = 0;
        for (int anArray : array) {
            if (anArray == 1) {
                break;
            } else {
                count++;
            }
        }

        int[] result = new int[array.length - count];
        System.arraycopy(array, count, result, 0, result.length);
        return result;
    }

    public static int[] toMutualOppositeForm(BigInteger integer) {
        int[] binaryArray = toBinaryArray(integer);
        int binaryLength = binaryArray.length;

        int[] ternaryArray = new int[binaryLength + 1];

        ternaryArray[0] = binaryArray[0];

        for (int i = 1; i < binaryLength; i++) {
            ternaryArray[i] = binaryArray[i] - binaryArray[i - 1];
        }

        ternaryArray[binaryLength] = -binaryArray[binaryLength - 1];

        return ternaryArray;
    }
}
