package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.Signature;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class SignatureEd25519Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_byte_array_32_32() {
        new SignatureEd25519(new byte[32], new byte[33]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_BigInteger() {
        new SignatureEd25519(new BigInteger("12345678901234567890123456789012"),
                new BigInteger("12345678901234567890123456789012L"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_one_byte_array() {
        new SignatureEd25519(new byte[63]);
        new SignatureEd25519(new byte[65]);
    }

    @Test
    public void success_GenerateSignature_from_one_byte_array() {
        Signature signature = new SignatureEd25519(new byte[64]);

        assertThat(signature.getBinaryR(), is(new byte[32]));
        assertThat(signature.getBinaryS(), is(new byte[32]));
    }

    @Test
    public void success_GenerateSignature_from_BigInteger() {
        BigInteger r = new BigInteger("21341234123123124123123124123412312312312321341234123123124123123124123412312");
        BigInteger s = new BigInteger("34321294125395128962341252349816946042634432134123412312312412312312412341231");

        assertThat(r.toByteArray().length, is(32));
        assertThat(s.toByteArray().length, is(32));

        Signature signature = new SignatureEd25519(r, s);

        assertThat(signature.getR(), is(r));
        assertThat(signature.getS(), is(s));
    }

    @Test
    public void success_GenerateSignature_from_two_byte_array() {
        SecureRandom random = new SecureRandom();
        byte[] input1 = new byte[32];
        byte[] input2 = new byte[32];
        random.nextBytes(input1);
        random.nextBytes(input2);
        Signature signature = new SignatureEd25519(input1, input2);

        assertThat(signature.getBinaryR(), is(input1));
        assertThat(signature.getBinaryS(), is(input2));
    }
}
