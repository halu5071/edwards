package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Ed25519Curve.class)
public class Ed25519CurveTest {

    private Curve curve;

    @Before
    public void setup() {
        curve = Ed25519Curve.getCurve();
    }

    @Test
    public void publicKeyByteLength() {
        assertThat(curve.getPublicKeyByteLength(), is(32));
    }

    @Test
    public void success_scalarMultiply_from_base_point() {
        byte[] seed = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);

        long start = System.currentTimeMillis();
        BigInteger baseX = curve.getBasePoint().getX().getInteger();
        BigInteger s = new BigInteger(seed);

        BigInteger result = baseX.multiply(s).mod(curve.getPrimePowerP());
        long end = System.currentTimeMillis();

        System.out.println("Measure: ScalarMultiply: " + (end - start) + " ms");
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
