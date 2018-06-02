package io.moatwel.crypto.eddsa.ed448;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.eddsa.Curve;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Ed448Curve.class)
public class Ed448CurveTest {

    private Curve curve;

    @Before
    public void setup() {
        curve = Ed448Curve.getCurve();
    }

    @Test
    public void publicKeyByteLength() {
        assertThat(curve.getPublicKeyByteLength(), is(57));
    }
}
