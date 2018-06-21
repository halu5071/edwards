package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.Signature;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class SignatureEd448Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_byte_array_57_56() {
        new SignatureEd448(new byte[57], new byte[56]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_BigInteger() {
        new SignatureEd448(new BigInteger("123456789012345678901234567890123456789012345678901234567"),
                new BigInteger("12345678901234567890123456789012345678901234567890123456"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_wrong_byte() {
        new SignatureEd448(new byte[113]);
    }

    @Test
    public void success_GenerateSignature_from_one_byte_array() {
        Signature signature = new SignatureEd448(new byte[114]);

        assertThat(signature.getBinaryR(), is(new byte[57]));
        assertThat(signature.getBinaryS(), is(new byte[57]));
    }

    @Test
    public void success_GenerateSignature_from_BigInteger() {
        BigInteger r = new BigInteger("12345678901234567890123456789012345678901234567890123456712345678901234567890123456789012345678901234567890123456712345678901234567890123");
        BigInteger s = new BigInteger("78901234567890123456789012123456123456789012345678901234534567890123456789012345671234567890123456789012345678901234567345678901234567890");

        assertThat(r.toByteArray().length, is(57));
        assertThat(s.toByteArray().length, is(57));

        Signature signature = new SignatureEd448(r, s);

        assertThat(signature.getR(), is(r));
        assertThat(signature.getS(), is(s));
    }

    @Test
    public void success_GenerateSignature_from_two_byte_array() {
        SecureRandom random = new SecureRandom();
        byte[] input1 = new byte[57];
        byte[] input2 = new byte[57];
        random.nextBytes(input1);
        random.nextBytes(input2);
        Signature signature = new SignatureEd448(input1, input2);

        assertThat(signature.getBinaryR(), is(input1));
        assertThat(signature.getBinaryS(), is(input2));
    }
}
