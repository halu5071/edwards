package io.moatwel.crypto.eddsa.ed448;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Curve;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448CurveTest {

    private Curve curve;

    @Before
    public void setup() {
        curve = Curve448.getInstance();
    }

    @Test
    public void publicKeyByteLength() {
        assertThat(curve.getPublicKeyByteLength(), is(57));
    }

    @Test
    public void success_GetA() {
        BigInteger integer = curve.getA();
        String str = integer.toString();
        assertThat(str, is("1"));
    }
}
