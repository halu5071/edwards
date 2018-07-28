package io.moatwel.crypto.eddsa;

import org.junit.Test;

public class DefaultHashProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateDefaultHashProvider() {
        new DefaultHashProvider(null);
    }
}
