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
        Signature signature = new SignatureEd25519(new BigInteger(input1), new BigInteger(input2));

        assertThat(signature.getR(), is(new BigInteger(input1)));
        assertThat(signature.getS(), is(new BigInteger(input2)));
    }
}
