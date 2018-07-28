package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.Signature;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class SignatureEd448Test {

    @Test
    public void success_GenerateSignature_from_BigInteger() {
        BigInteger r = new BigInteger("12345678901234567890123456789012345678901234567890123456712345678901234567890123456789012345678901234567890123456712345678901234567890123");
        BigInteger s = new BigInteger("78901234567890123456789012123456123456789012345678901234534567890123456789012345671234567890123456789012345678901234567345678901234567890");

        assertThat(r.toByteArray().length, is(57));
        assertThat(s.toByteArray().length, is(57));

        Signature signature = new SignatureEd448(r, s);

        assertThat(signature.getIntegerR(), is(r));
        assertThat(signature.getIntegerS(), is(s));
    }

    @Test
    public void success_GenerateSignature_from_two_byte_array() {
        SecureRandom random = new SecureRandom();
        byte[] input1 = new byte[57];
        byte[] input2 = new byte[57];
        random.nextBytes(input1);
        random.nextBytes(input2);
        Signature signature = new SignatureEd448(new BigInteger(input1), new BigInteger(input2));

        assertThat(signature.getIntegerR(), is(new BigInteger(1, input1)));
        assertThat(signature.getIntegerS(), is(new BigInteger(1, input2)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_1() {
        byte[] r = new byte[56];
        byte[] s = new byte[57];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_2() {
        byte[] r = new byte[57];
        byte[] s = new byte[58];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_3() {
        byte[] r = new byte[57];
        byte[] s = new byte[56];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_4() {
        byte[] r = new byte[56];
        byte[] s = new byte[57];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_5() {
        byte[] r = new byte[58];
        byte[] s = new byte[56];

        new SignatureEd448(r, s);
    }

    @Test
    public void success_JoinSignature() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78, 37, 13, -19, 20, 21, -82, 3, 43, 62, 73, -2, -15, 23, 53, 63, 31, 91, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 51, 53, 79, 10, -31, 23, -52, 1, -4, 24, 38, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        Signature signature = new SignatureEd448(input1, input2);

        assertNotNull(signature);

        byte[] result = signature.getSignature();

        assertThat(result.length, is(114));
        assertThat(result, is(new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78, 37, 13, -19, 20, 21, -82, 3, 43, 62, 73, -2, -15, 23, 53, 63, 31, 91, 94, -5, 26, 57, 18, 91, 110, 78,
                -82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 51, 53, 79, 10, -31, 23, -52, 1, -4, 24, 38, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38}));
    }

}
