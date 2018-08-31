package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519CurveTest {

    private Curve curve;

    @Before
    public void setup() {
        curve = Curve25519.getInstance();
    }

    @Test
    public void publicKeyByteLength() {
        assertThat(curve.getPublicKeyByteLength(), is(32));
    }

    @Test
    public void check_D() {
        assertThat(curve.getD().getInteger(),
                is(new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555")));
    }

    @Test
    public void success_EncodeBasePoint() {
        EncodedPoint encodedPoint = curve.getBasePoint().encode();

        assertThat(encodedPoint.getValue(), is(new byte[]{88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102}));
    }
}
