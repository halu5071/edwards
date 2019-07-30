package io.moatwel.crypto.eddsa.ed25519.nem;

import io.moatwel.crypto.eddsa.SchemeProvider;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class NemV2SchemeProviderTest {

    @Test
    public void success_GetNonNullDelegate() {
        SchemeProvider provider = new NemV2SchemeProvider();

        assertNotNull(provider);
    }
}
