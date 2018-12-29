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

    public static byte[] join(byte[]... inputs) {
        byte[] result = new byte[0];
        for (byte[] input : inputs) {
            result = join(result, input);
        }
        return result;
    }

    public static byte[] paddingZeroOnHead(byte[] input, int byteLength) {
        if (input.length > byteLength) {
            throw new IllegalArgumentException("input byte array must have length which is less than byteLength you want to be.");
        }
        byte[] padding = new byte[byteLength - input.length];
        return join(padding, input);
    }

    public static byte[] paddingZeroOnTail(byte[] input, int byteLength) {
        if (input.length > byteLength) {
            throw new IllegalArgumentException("input byte array must have length which is less than byteLength you want to be.");
        }
        byte[] padding = new byte[byteLength - input.length];
        return join(input, padding);
    }

    /**
     * Read bit value from one byte.
     * <p>Java can not handle unsigned byte, so
     *
     * @param value    target byte.
     * @param position target position to read.
     * @return read bit value 0 or 1.
     */
    public static int readBit(byte value, int position) {
        if (position > 7 || position < 0) {
            throw new ArrayIndexOutOfBoundsException("position must be 0 - 7.");
        }
        byte[] data = new byte[2];
        data[1] = value;
        int dataValue = new BigInteger(data).intValue();
        return dataValue >>> position;
    }
}
