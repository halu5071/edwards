package io.moatwel.util;

import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

public class ArrayUtilsTest {

    @Test
    public void success_ToByteArray_from_BigInteger_1() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};
        byte[] input3 = new byte[]{0, -4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};
        byte[] input4 = new byte[]{-34, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        BigInteger integer1 = new BigInteger(1, input1);
        BigInteger integer2 = new BigInteger(1, input2);
        BigInteger integer3 = new BigInteger(1, input3);
        BigInteger integer4 = new BigInteger(1, input4);

        assertThat(integer1.toByteArray(), is(input1));
        assertThat(integer2.toByteArray(), not(input2));
        assertThat(integer3.toByteArray(), is(input3));
        assertThat(integer4.toByteArray(), not(input4));

        assertThat(ArrayUtils.toByteArray(integer1, 32), is(input1));
        assertThat(ArrayUtils.toByteArray(integer2, 32), is(input2));
        assertThat(ArrayUtils.toByteArray(integer3, 32), is(input3));
        assertThat(ArrayUtils.toByteArray(integer4, 32), is(input4));
    }

    @Test
    public void success_ToByteArray_from_BigInteger_2() {
        byte[] input1 = new byte[]{5, -4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};
        byte[] expectedOutput1 = new byte[]{5, -4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13};

        byte[] input2 = new byte[]{-34, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};
        byte[] expectedOutput2 = new byte[]{-34, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13};

        BigInteger integer1 = new BigInteger(1, input1);
        BigInteger integer2 = new BigInteger(1, input2);

        assertThat(integer1.toByteArray(), is(input1));
        assertThat(integer2.toByteArray(), not(input2));

        assertThat(ArrayUtils.toByteArray(integer1, 31), is(expectedOutput1));
        assertThat(ArrayUtils.toByteArray(integer2, 31), is(expectedOutput2));
    }

    @Test
    public void success_SplitByteArray_1() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};

        byte[] result1 = ArrayUtils.split(input1, 10)[0];
        byte[] result2 = ArrayUtils.split(input1, 10)[1];

        assertThat(result1, is(new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3}));
        assertThat(result2, is(new byte[]{67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78}));
    }

    @Test
    public void success_toBinaryArray() {
        BigInteger integer = new BigInteger("2");   // 00000010
        BigInteger integer1 = new BigInteger("17"); // 00010001
        BigInteger integer2 = new BigInteger("257"); // 0000000100000001
        BigInteger integer3 = new BigInteger("256"); // 0000000100000000

        int[] result = ArrayUtils.toBinaryArray(integer);
        int[] result1 = ArrayUtils.toBinaryArray(integer1);
        int[] result2 = ArrayUtils.toBinaryArray(integer2);
        int[] result3 = ArrayUtils.toBinaryArray(integer3);

        assertThat(result, is(new int[]{1, 0}));
        assertThat(result1, is(new int[]{1, 0, 0, 0, 1}));
        assertThat(result2, is(new int[]{1, 0, 0, 0, 0, 0, 0, 0, 1}));
        assertThat(result3, is(new int[]{1, 0, 0, 0, 0, 0, 0, 0, 0}));
    }

    @Test
    public void success_toMutualOppositeForm() {
        BigInteger integer1 = new BigInteger("27");
        BigInteger integer2 = new BigInteger("11");
        BigInteger integer3 = new BigInteger("247");
        BigInteger integer4 = new BigInteger("327");

        int[] result1 = ArrayUtils.toMutualOppositeForm(integer1);
        int[] result2 = ArrayUtils.toMutualOppositeForm(integer2);
        int[] result3 = ArrayUtils.toMutualOppositeForm(integer3);
        int[] result4 = ArrayUtils.toMutualOppositeForm(integer4);

        assertThat(result1, is(new int[]{1, 0, -1, 1, 0, -1}));
        assertThat(result2, is(new int[]{1, -1, 1, 0, -1}));
        assertThat(result3, is(new int[]{1, 0, 0, 0, -1, 1, 0, 0, -1}));
        assertThat(result4, is(new int[]{1, -1, 1, -1, 0, 0, 1, 0, 0, -1}));
    }

    @Test
    public void success_ReverseIntegerArray() {
        int[] input1 = new int[]{0, 1, 1, -1, 0, 0, -1};
        assertThat(ArrayUtils.reverse(input1), is(new int[]{-1, 0, 0, -1, 1, 1, 0}));

        int[] input2 = new int[]{0, -1, 1, -1, 0, 1, -1, 1, 1, 1, 0, -1, -1, 0};
        assertThat(ArrayUtils.reverse(input2), is(new int[]{0, -1, -1, 0, 1, 1, 1, -1, 1, 0, -1, 1, -1, 0}));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_SplitByteArray_wrong_expected_length_1() {
        byte[] input = new byte[]{1, 2, 3, 4, 5};

        ArrayUtils.split(input, 8);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_SplitByteArray_wrong_range_1() {
        byte[] input = new byte[]{1, 2, 3, 4, 5, 6};
        ArrayUtils.split(input, -1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_SplitByteArray_wrong_range_2() {
        byte[] input = new byte[]{1, 2, 3, 4, 5, 6};
        ArrayUtils.split(input, 9);
    }
}
