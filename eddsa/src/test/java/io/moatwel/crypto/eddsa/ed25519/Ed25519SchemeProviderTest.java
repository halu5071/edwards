package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class Ed25519SchemeProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed25519SchemeProvider(null);
    }

    @Test
    public void success_GeneratePrivateKey() {
        SchemeProvider provider = new Ed25519SchemeProvider(HashAlgorithm.KECCAK_512);
        PrivateKey privateKey = provider.generatePrivateKey();

        assertNotNull(privateKey);
        assertThat((privateKey instanceof PrivateKeyEd25519), is(true));
    }

    @Test
    public void success_GetSigner() {
        SchemeProvider provider = new Ed25519SchemeProvider(HashAlgorithm.KECCAK_512);
        EdDsaSigner signer = provider.getSigner();

        assertNotNull(signer);
    }


    @Test
    public void success_dom_1() {
        SchemeProvider schemeProvider = new Ed25519SchemeProvider(HashAlgorithm.KECCAK_512);
        byte[] dom = schemeProvider.dom(new byte[0]);

        assertThat(HexEncoder.getString(dom), is(""));
    }
}
