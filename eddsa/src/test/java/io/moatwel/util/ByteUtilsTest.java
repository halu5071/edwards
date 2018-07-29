package io.moatwel.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class ByteUtilsTest {

    @Test
    public void success_SplitByteArray() {
        byte[] input = new byte[]{32, 43, 53, 56, 34, 23, 43, 93, 42, 42};
        byte[][] result = ByteUtils.split(input, 5);

        assertThat(result[0], is(new byte[]{32, 43, 53, 56, 34}));
        assertThat(result[1], is(new byte[]{23, 43, 93, 42, 42}));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void failure_SplitByteArray() {
        byte[] input = new byte[]{32, 43, 53, 56, 34, 23, 43};
        ByteUtils.split(input, 8);
    }

    @Test
    public void success_reverse() {
        byte[] input = new byte[]{26, 94, 11, 65, 43, 13, 62, 53, 13, 43};
        assertThat(ByteUtils.reverse(input), is(new byte[]{43, 13, 53, 62, 13, 43, 65, 11, 94, 26}));
        byte[] input2 = new byte[]{54, 25, 53, 91, 24, 42, 51, 51, 54, 41, 35, 30, 45, 14, 34, 53};
        assertThat(ByteUtils.reverse(input2), is(new byte[]{53, 34, 14, 45, 30, 35, 41, 54, 51, 51, 42, 24, 91, 53, 25, 54}));
    }

    @Test
    public void success_LittleEndian() {
        byte[] input = new byte[]{0, 0, 10, 20};
        byte[] input2 = new byte[]{20, 10, 0, 0};
        ByteBuffer buffer = ByteBuffer.wrap(input);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int output1 = buffer.getInt();
        int output2 = ByteBuffer.wrap(input2).getInt();

        assertEquals(output1, output2);
    }

    @Test
    public void success_ReverseByteArrayToBigInteger() {
        byte[] input = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        byte[] input2 = new byte[]{31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
        BigInteger integer1 = new BigInteger(input);
        BigInteger integer2 = new BigInteger(ByteUtils.reverse(input2));

        assertEquals(integer1, integer2);
    }

    @Test
    public void success_JoinByteArray() {
        byte[] input1 = new byte[]{1, 2, 3, 4, 5};
        byte[] input2 = new byte[]{6, 7, 8, 9, 10};

        byte[] result = ByteUtils.join(input1, input2);

        assertThat(result, is(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
    }

    @Test
    public void success_PaddingZeroArray() {
        byte[] input = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

        byte[] result = ByteUtils.paddingZero(input, 10);
        byte[] result2 = ByteUtils.paddingZero(input, 20);

        assertThat(result, is(new byte[]{0, 0, 1, 2, 3, 4, 5, 6, 7, 8}));
        assertThat(result2, is(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_PaddingZeroArray_larger_than_specified_length() {
        byte[] input = new byte[10];

        ByteUtils.paddingZero(input, 8);
    }

    @Test
    public void success_toBinaryArray() {
        BigInteger integer = new BigInteger("2");   // 00000010
        BigInteger integer1 = new BigInteger("17"); // 00010001
        BigInteger integer2 = new BigInteger("257"); // 0000000100000001
        BigInteger integer3 = new BigInteger("256"); // 0000000100000000

        int[] result = ByteUtils.toBinaryArray(integer);
        int[] result1 = ByteUtils.toBinaryArray(integer1);
        int[] result2 = ByteUtils.toBinaryArray(integer2);
        int[] result3 = ByteUtils.toBinaryArray(integer3);

        assertThat(result, is(new int[]{1, 0}));
        assertThat(result1, is(new int[]{1, 0, 0, 0, 1}));
        assertThat(result2, is(new int[]{1, 0, 0, 0, 0, 0, 0, 0, 1}));
        assertThat(result3, is(new int[]{1, 0, 0, 0, 0, 0, 0, 0, 0}));
    }

    @Test
    public void success_ReadBit() {
        byte value = 0b01010101;

        int readBit1 = ByteUtils.readBit(value, 7);
        int readBit2 = ByteUtils.readBit(value, 6);

        assertThat(readBit1, is(0));
        assertThat(readBit2, is(1));
    }
}
