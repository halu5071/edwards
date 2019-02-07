package io.moatwel.crypto.eddsa.ed25519.ph;

import org.junit.Test;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.SchemeProvider;

import static org.junit.Assert.assertNotNull;

public class Ed25519phSchemeProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed25519phSchemeProvider(null);
    }

    @Test
    public void success_GetSigner() {
        SchemeProvider schemeProvider = new Ed25519phSchemeProvider(HashAlgorithm.SHAKE_256);
        assertNotNull(schemeProvider.getSigner());
    }

    @Test
    public void success_GenerateRandomPrivateKey() {
        SchemeProvider schemeProvider = new Ed25519phSchemeProvider(HashAlgorithm.SHAKE_256);
        PrivateKey privateKey = schemeProvider.generatePrivateKey();

        assertNotNull(privateKey);
    }
}
