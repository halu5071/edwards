package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.eddsa.Curve;

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
        curve = Ed25519Curve.getEdCurve();
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
}
