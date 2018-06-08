package io.moatwel.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Signature.class)
public class SignatureTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_byte_array_32_32() {
        new Signature(new byte[32], new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_byte_array_64() {
        new Signature(new byte[63]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_CreateSignature_wrong_BigInteger() {
        new Signature(new BigInteger("12345678901234567890123456789012"),
                new BigInteger("12345678901234567890123456789012L"));
    }

    @Test
    public void sample() {
        BigInteger maxValue = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        BigInteger integer = new BigInteger("12345678901234567890123456789012");
        assertThat(integer.compareTo(maxValue), is(-1));
        BigInteger integer2 = new BigInteger("12345678");
        assertThat(integer.compareTo(maxValue), is(-1));
    }
}
