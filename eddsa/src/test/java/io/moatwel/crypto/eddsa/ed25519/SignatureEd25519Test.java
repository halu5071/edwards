package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class SignatureEd25519Test {

    @Test
    public void success_GenerateSignature_from_BigInteger() {
        BigInteger r = new BigInteger("21341234123123124123123124123412312312312321341234123123124123123124123412312");
        BigInteger s = new BigInteger("34321294125395128962341252349816946042634432134123412312312412312312412341231");

        assertThat(r.toByteArray().length, is(32));
        assertThat(s.toByteArray().length, is(32));

        Signature signature = new SignatureEd25519(r, s);

        assertThat(signature.getIntegerR(), is(r));
        assertThat(signature.getIntegerS(), is(s));
    }

    @Test
    public void success_GenerateSignature_from_two_byte_array() {
        SecureRandom random = new SecureRandom();
        byte[] input1 = new byte[32];
        byte[] input2 = new byte[32];
        random.nextBytes(input1);
        random.nextBytes(input2);
        Signature signature = new SignatureEd25519(input1, input2);

        assertThat(signature.getIntegerR(), is(new BigInteger(1, input1)));
        assertThat(signature.getIntegerS(), is(new BigInteger(1, input2)));
    }

    @Test
    public void success_GenerateSignature_from_two_byte_array_1() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        Signature signature = new SignatureEd25519(new BigInteger(input1), new BigInteger(input2));

        assertThat(signature.getIntegerR(), is(new BigInteger(1, input1)));
        assertThat(signature.getIntegerS(), is(new BigInteger(1, input2)));

        byte[] result1 = signature.getR();
        byte[] result2 = signature.getS();

        assertThat(result1, is(input1));
        assertThat(result2, is(input2));

        byte[] trueResult1 = signature.getR();
        byte[] trueResult2 = signature.getS();

        assertThat(trueResult1, is(input1));
        assertThat(trueResult2, is(input2));
    }

    @Test
    public void success_GenerateSignature_from_two_byte_array_2() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        Signature signature = new SignatureEd25519(input1, input2);

        BigInteger r = signature.getIntegerR();
        BigInteger s = signature.getIntegerS();

        assertThat(input1, is(ArrayUtils.toByteArray(r, 32)));
        assertThat(input2, is(ArrayUtils.toByteArray(s, 32)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_1() {
        byte[] r = new byte[33];
        byte[] s = new byte[32];

        new SignatureEd25519(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_2() {
        byte[] r = new byte[32];
        byte[] s = new byte[33];

        new SignatureEd25519(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_3() {
        byte[] r = new byte[32];
        byte[] s = new byte[31];

        new SignatureEd25519(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_4() {
        byte[] r = new byte[31];
        byte[] s = new byte[32];

        new SignatureEd25519(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_5() {
        byte[] r = new byte[33];
        byte[] s = new byte[31];

        new SignatureEd25519(r, s);
    }

    @Test
    public void success_JoinSignature() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        Signature signature = new SignatureEd25519(input1, input2);

        byte[] result = signature.getSignature();

        assertThat(result.length, is(64));
        assertThat(result, is(new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78,
                -82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38}));
    }
}
