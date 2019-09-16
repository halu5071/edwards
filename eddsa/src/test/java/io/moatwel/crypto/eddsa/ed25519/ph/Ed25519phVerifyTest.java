package io.moatwel.crypto.eddsa.ed25519.ph;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Signer;
import io.moatwel.util.HexEncoder;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519phVerifyTest {

    private KeyPair pair;
    private EdDsaSigner signer = new Ed25519Signer(HashAlgorithm.SHA_512, new Ed25519phSchemeProvider(HashAlgorithm.SHA_512));
    private Edwards edwards = new Edwards(new Ed25519phSchemeProvider(HashAlgorithm.SHA_512));

    @Before
    public void setup() {
        PrivateKey privateKey = PrivateKey.newInstance("0305334e381af78f14abb666f6199f57bc3495335a256a95bd2a55bf546663f6");
        pair = edwards.generateKeyPair(privateKey);
    }

    @Test
    public void success_VerifyMessage_1() {
        Signature signature = signer.sign(pair, "demo".getBytes(), null);

        boolean isVerified = signer.verify(pair.getPublicKey(), "demo".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifyMessage_2() {
        Signature signature = signer.sign(pair, "This is a pen.".getBytes(), null);

        boolean isVerified = signer.verify(pair.getPublicKey(), "This is a pen.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifyMessage_3() {
        Signature signature = signer.sign(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null);

        boolean isVerified = signer.verify(pair.getPublicKey(), "falkdjflasdjl ko3ii;afd".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void failure_VerifyMessage_1() {
        Signature signature = signer.sign(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null);

        boolean isVerified = signer.verify(pair.getPublicKey(), "falkdjflasdjl ko3ii;afd.".getBytes(), null, signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifyMessage_2() {
        Signature signature = signer.sign(pair, "falkdjflasdjl ko3ii;afd".getBytes(), null);

        boolean isVerified = signer.verify(pair.getPublicKey(), "falkdjflasdjl ko3ii;afd".getBytes(), HexEncoder.getBytes("ab"), signature);

        assertThat(isVerified, is(false));
    }
}
