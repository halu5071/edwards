package io.moatwel.util;

import java.math.BigInteger;

public class ByteUtils {

    public static byte[][] split(byte[] input, int firstLength) {
        if (input.length < firstLength) {
            throw new ArrayIndexOutOfBoundsException("Specified index over input length");
        }
        byte[] first = new byte[firstLength];
        byte[] second = new byte[input.length - firstLength];

        System.arraycopy(input, 0, first, 0, firstLength);
        System.arraycopy(input, firstLength, second, 0, input.length - firstLength);
        return new byte[][]{first, second};
    }

    public static byte[] reverse(byte[] input) {
        byte[] output = new byte[input.length];
        int counter = 0;
        for (byte b : input) {
            output[input.length - counter - 1] = b;
            counter++;
        }
        return output;
    }

    public static byte[] join(byte[] value1, byte[] value2) {
        int length = value1.length + value2.length;
        byte[] result = new byte[length];
        System.arraycopy(value1, 0, result, 0, value1.length);
        System.arraycopy(value2, 0, result, value1.length, value2.length);
        return result;
    }

    public static byte[] paddingZero(byte[] input, int byteLength) {
        if (input.length > byteLength) {
            throw new IllegalArgumentException("input byte array must have length which is less than byteLength you want to be.");
        }
        byte[] padding = new byte[byteLength - input.length];
        return join(padding, input);
    }

    public static int[] toBinaryArray(BigInteger integer) {
        byte[] tmp = integer.toByteArray();
        int[] array = new int[tmp.length * 8];
        for (int i = 0; i < tmp.length; i++) {
            for (int j = 0; j < 8; j++) {
                array[i * 8 + j] = (tmp[i] & 0x80)/0x80;
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
}
