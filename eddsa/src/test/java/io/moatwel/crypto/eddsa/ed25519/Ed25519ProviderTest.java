package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

public class Ed25519ProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed25519Provider(null);
    }
}
