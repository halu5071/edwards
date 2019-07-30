package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.HexEncoder;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448SchemeProviderTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_NullHashAlgorithm() {
        new Ed448SchemeProvider(null);
    }

    @Test
    public void success_dom_1() {
        SchemeProvider schemeProvider = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);
        byte[] dom = schemeProvider.dom(new byte[0]);

        assertThat(HexEncoder.getString(dom), is("53696745643434380000"));
    }

    @Test
    public void success_dom_2() {
        byte[] value = HexEncoder.getBytes("666f6f");
        SchemeProvider schemeProvider = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);
        byte[] dom = schemeProvider.dom(value);

        assertThat(HexEncoder.getString(dom), is("53696745643434380003666f6f"));
    }
}
