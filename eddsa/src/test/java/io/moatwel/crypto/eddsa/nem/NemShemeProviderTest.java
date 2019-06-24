package io.moatwel.crypto.eddsa.nem;

import org.junit.Test;

import io.moatwel.crypto.eddsa.SchemeProvider;

import static org.junit.Assert.assertNotNull;

public class NemShemeProviderTest {

    @Test
    public void success_GetNonNullDelegate() {
        SchemeProvider provider = new NemSchemeProvider();

        assertNotNull(provider);
    }
}
