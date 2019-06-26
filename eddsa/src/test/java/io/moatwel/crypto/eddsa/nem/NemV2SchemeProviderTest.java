package io.moatwel.crypto.eddsa.nem;

import org.junit.Test;

import io.moatwel.crypto.eddsa.SchemeProvider;

import static org.junit.Assert.assertNotNull;

public class NemV2SchemeProviderTest {

    @Test
    public void success_GetNonNullDelegate() {
        SchemeProvider provider = new NemV2SchemeProvider();

        assertNotNull(provider);
    }
}
