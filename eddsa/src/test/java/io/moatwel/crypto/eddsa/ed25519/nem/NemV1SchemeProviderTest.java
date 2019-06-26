package io.moatwel.crypto.eddsa.ed25519.nem;

import org.junit.Test;

import io.moatwel.crypto.eddsa.SchemeProvider;

import static org.junit.Assert.assertNotNull;

public class NemV1SchemeProviderTest {

    @Test
    public void success_GetNonNullDelegate() {
        SchemeProvider provider = new NemV1SchemeProvider();

        assertNotNull(provider);
    }
}
