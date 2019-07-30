package io.moatwel.crypto.eddsa.ed448.ph;

import io.moatwel.crypto.*;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.ed448.Ed448Signer;
import io.moatwel.util.HexEncoder;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448phVerifyTest {

    private KeyPair pair;
    private EdDsaSigner signer = new Ed448Signer(HashAlgorithm.SHAKE_256, new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256));
    private Edwards edwards = new Edwards(new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256));

    @Before
    public void setup() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "833fe62409237b9d62ec77587520911e" +
                        "9a759cec1d19755b7da901b96dca3d42" +
                        "ef7822e0d5104127dc05d6dbefde69e3" +
                        "ab2cec7c867c6e2c49");
        pair = edwards.generateKeyPair(privateKey);
    }

    @Test
    public void success_VerifyMessage_1() {
        Signature signature = signer.sign(pair, "demo".getBytes(), null);

        boolean isVerified = signer.verify(pair, "demo".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifyMessage_2() {
        Signature signature = signer.sign(pair, "This is a pen.".getBytes(), null);

        boolean isVerified = signer.verify(pair, "This is a pen.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifyMessage_3() {
        Signature signature = signer.sign(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null);

        boolean isVerified = signer.verify(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void failure_VerifyMessage_1() {
        Signature signature = signer.sign(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null);

        boolean isVerified = signer.verify(pair, "falkdjflasdjl ko3ii;afd.".getBytes(), null, signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifyMessage_2() {
        Signature signature = signer.sign(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null);

        boolean isVerified = signer.verify(pair, "falkdjflasdjl ko3ii;afd".getBytes(), HexEncoder.getBytes("ab"), signature);

        assertThat(isVerified, is(false));
    }
}
