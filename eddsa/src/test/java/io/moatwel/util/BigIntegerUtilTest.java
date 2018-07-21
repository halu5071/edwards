package io.moatwel.util;

import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

public class BigIntegerUtilTest {

    @Test
    public void success_GenerateBigInteger_from_byte_array() {
        byte[] input1 = new byte[]{1, 12, 3, 64, 35, 26, 7, -8, 9, 10, 121, -12, 113, 10, 14, 15};
        byte[] input2 = new byte[]{0, -11, 72, 13, 14, 35, 6, 27, 80, 9, 20, 51, 112, 13, 64, -15};
        byte[] input3 = new byte[]{0, -125, -111, -115};
        byte[] input5 = new byte[]{-29, 125, 72, 13, 112, 13, 14, 35, 6, 27, 80, 9, 20, 51, 64, -15};
        byte[] input6 = new byte[]{109, -42, 72, 13, 112, 13, 14, 35, 6, 27, 80, 9, 20, 51, 64, -15};

        BigInteger integer1 = new BigInteger(input1);
        BigInteger integer2 = new BigInteger(input2);
        BigInteger integer3 = new BigInteger(input3);
        BigInteger integer5 = new BigInteger(input5);
        BigInteger integer6 = new BigInteger(input6);

        assertThat(integer1.toByteArray(), is(input1));
        assertThat(integer2.toByteArray(), is(input2));
        assertThat(integer3.toByteArray(), is(input3));
        assertThat(integer5.toByteArray(), is(input5));
        assertThat(integer6.toByteArray(), is(input6));

        BigInteger result = new BigInteger("8622477");
        byte[] re = result.toByteArray();
    }

    @Test
    public void failure_GenerateBigInteger_from_byte_array() {
        byte[] input2 = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] input3 = new byte[]{0, 11, 72, 13, 14, 35, 6, 27, 80, 9, 20, 51, 112, 13, 64, -15};
        byte[] input4 = new byte[]{0, 125, 72, 13, 112, 13, 14, 35, 6, 27, 80, 9, 20, 51, 64, -15};
        byte[] input5 = new byte[]{0, 27, 51, 64, -15};
        byte[] input6 = new byte[]{27, 51, 64, -15};

        BigInteger integer2 = new BigInteger(input2);
        BigInteger integer3 = new BigInteger(input3);
        BigInteger integer4 = new BigInteger(input4);
        BigInteger integer5 = new BigInteger(input5);
        BigInteger integer7 = new BigInteger(input6);

        assertThat(integer2.toByteArray(), not(input2));
        assertThat(integer3.toByteArray(), not(input3));
        assertThat(integer4.toByteArray(), not(input4));
        assertThat(integer5.toByteArray(), not(input5));

        BigInteger integer6 = new BigInteger("456343793");
        byte[] result = integer6.toByteArray();
    }

    @Test
    public void failure_GenerateBigInteger_from_byte_array_2() {
        byte[] input2 = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] input3 = new byte[]{0, 11, 72, 13, 14, 35, 6, 27, 80, 9, 20, 51, 112, 13, 64, -15};
        byte[] input4 = new byte[]{0, 125, 72, 13, 112, 13, 14, 35, 6, 27, 80, 9, 20, 51, 64, -15};
        byte[] input5 = new byte[]{0, 8, 72, 13, 112, 13, 14, 35, 6, 27, 80, 9, 20, 51, 64, -15};

        BigInteger integer2 = new BigInteger(input2);
        BigInteger integer3 = new BigInteger(1, input3);
        BigInteger integer4 = new BigInteger(input4);
        BigInteger integer5 = new BigInteger(input5);

        assertThat(parse(integer2), not(input2));
        assertThat(integer3.toByteArray(), not(input3));
        assertThat(integer4.toByteArray(), not(input4));
        assertThat(integer5.toByteArray(), not(input5));
    }

    private byte[] parse(BigInteger integer) {
        if (integer.compareTo(BigInteger.ZERO) < 0) {
            integer = integer.add(BigInteger.ONE.shiftLeft(64));
        }

        return integer.toByteArray();
    }

    @Test
    public void test() {
        BigInteger integer = new BigInteger("4105090635616705429695061053659558245554003651275941563464146285782036767247");
        byte[] result = integer.toByteArray();
    }
}
