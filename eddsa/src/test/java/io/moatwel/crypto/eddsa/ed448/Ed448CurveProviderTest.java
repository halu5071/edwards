package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

public class Ed448CurveProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed448CurveProvider(null);
    }
}
