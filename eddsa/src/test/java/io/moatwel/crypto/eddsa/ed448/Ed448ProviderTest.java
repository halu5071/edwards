package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

public class Ed448ProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed448Provider(null);
    }
}
