package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class SignatureEd25519Test {

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

    @Test
    public void success_GenerateSignature_from_BigInteger() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};
        BigInteger integer1 = new BigInteger(1, input1);
        BigInteger integer2 = new BigInteger(1, input2);

        Signature signature = new SignatureEd25519(integer1, integer2);

        assertThat(signature.getSignature().length, is(64));
        assertThat(signature.getSignature(), is(new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78,
                -82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38}));
    }

    @Test
    public void success_SignatureAsString() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        Signature signature = new SignatureEd25519(input1, input2);
        String str = signature.asString();

        assertThat(str, is("13f0521718fb3e1152034379f0ad0e19f3250ded1415ae035efb1a39125b6e4eae04ea035e8dea1b0c23f201e603d40d8fe15d1d02dfb82a0ef70d28e44ff326"));
    }
}
