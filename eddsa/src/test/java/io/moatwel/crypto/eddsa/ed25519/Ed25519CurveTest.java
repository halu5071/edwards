package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

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
        BigInteger baseX = new BigInteger(curve.getBasePoint().getX().getValue());
        BigInteger s = new BigInteger(seed);

        BigInteger result = baseX.multiply(s).mod(curve.getPrimePowerP());
        long end = System.currentTimeMillis();

        System.out.println("Result: " + (end - start) + " millsec");
        System.out.println("bitLength: " + result.toByteArray().length);
    }

    @Test
    public void check_D() {
        assertThat(curve.getD().getInteger(),
                is(new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555")));
    }

    @Test
    public void measure_CalculateModulo() {
        long start = System.currentTimeMillis();

        for (int i = 0; i < 10000; i++) {
            BigInteger d = new BigInteger("-121665")
                    .multiply(new BigInteger("121666").modInverse(curve.getPrimePowerP()))
                    .mod(curve.getPrimePowerP());
        }

        long end = System.currentTimeMillis();

        System.out.println("Calculate Result: " + (end - start) / 10000.0 + " ms");
    }

    @Test
    public void success_EncodeBasePoint() {
        EncodedPoint encodedPoint = curve.getBasePoint().encode();

        assertThat(encodedPoint.getValue(), is(new byte[]{88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102}));
    }
}
