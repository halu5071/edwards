package io.moatwel.crypto.eddsa.ed448.ph;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.SchemeProvider;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class Ed448phSchemeProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed448phSchemeProvider(null);
    }

    @Test
    public void success_GetSigner() {
        SchemeProvider schemeProvider = new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256);

        assertNotNull(schemeProvider.getSigner());
    }

    @Test
    public void success_GenerateRandomPrivateKey() {
        SchemeProvider schemeProvider = new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256);
        PrivateKey privateKey = schemeProvider.generatePrivateKey();

        assertNotNull(privateKey);
    }
}
