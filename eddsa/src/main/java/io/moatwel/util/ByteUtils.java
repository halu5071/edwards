package io.moatwel.util;

public class ByteUtils {

    public static int isEqualConstantTime(final int b, final int c) { // ok
        int result = 0;
        final int xor = b ^ c;
        for (int i = 0; i < 8; i++) {
            result |= xor >> i;
        }

        return (result ^ 0x01) & 0x01;
    }

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
}
