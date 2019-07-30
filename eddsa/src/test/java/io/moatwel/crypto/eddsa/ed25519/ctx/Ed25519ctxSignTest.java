package io.moatwel.crypto.eddsa.ed25519.ctx;

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

public class Ed25519ctxSignTest {

    private Edwards edwards;
    private EdDsaSigner signer = new Ed25519Signer(HashAlgorithm.SHA_512, new Ed25519ctxSchemeProvider(HashAlgorithm.SHA_512));

    @Before
    public void setup() {
        edwards = new Edwards(new Ed25519ctxSchemeProvider(HashAlgorithm.SHA_512));
    }

    @Test
    public void success_SignMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292"));

        byte[] message = HexEncoder.getBytes("f726936d19c800494e3fdaff20b276a8");
        byte[] context = HexEncoder.getBytes("666f6f");
        Signature signature = signer.sign(keyPair, message, context);

        byte[] r = signature.getR();
        byte[] s = signature.getS();

        assertThat(HexEncoder.getString(r), is(
                "55a4cc2f70a54e04288c5f4cd1e45a7b" +
                        "b520b36292911876cada7323198dd87a"));
        assertThat(HexEncoder.getString(s), is(
                "8b36950b95130022907a7fb7c4e9b2d5" +
                        "f6cca685a587b4b21f4b888e4e7edb0d"));
    }

    @Test
    public void success_SignMessage_2() {
        PrivateKey privateKey = PrivateKey.newInstance("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292"));

        byte[] message = HexEncoder.getBytes("f726936d19c800494e3fdaff20b276a8");
        byte[] context = HexEncoder.getBytes("626172");
        Signature signature = signer.sign(keyPair, message, context);

        byte[] r = signature.getR();
        byte[] s = signature.getS();

        assertThat(HexEncoder.getString(r), is(
                "fc60d5872fc46b3aa69f8b5b4351d580" +
                        "8f92bcc044606db097abab6dbcb1aee3"));
        assertThat(HexEncoder.getString(s), is(
                "216c48e8b3b66431b5b186d1d28f8ee1" +
                        "5a5ca2df6668346291c2043d4eb3e90d"));
    }

    @Test
    public void success_SignMessage_3() {
        PrivateKey privateKey = PrivateKey.newInstance("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292"));

        byte[] message = HexEncoder.getBytes("508e9e6882b979fea900f62adceaca35");
        byte[] context = HexEncoder.getBytes("666f6f");
        Signature signature = signer.sign(keyPair, message, context);

        byte[] r = signature.getR();
        byte[] s = signature.getS();

        assertThat(HexEncoder.getString(r), is(
                "8b70c1cc8310e1de20ac53ce28ae6e72" +
                        "07f33c3295e03bb5c0732a1d20dc6490"));
        assertThat(HexEncoder.getString(s), is(
                "8922a8b052cf99b7c4fe107a5abb5b2c" +
                        "4085ae75890d02df26269d8945f84b0b"));
    }

    @Test
    public void success_SignMessage_4() {
        PrivateKey privateKey = PrivateKey.newInstance("ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is("0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772"));

        byte[] message = HexEncoder.getBytes("f726936d19c800494e3fdaff20b276a8");
        byte[] context = HexEncoder.getBytes("666f6f");
        Signature signature = signer.sign(keyPair, message, context);

        byte[] r = signature.getR();
        byte[] s = signature.getS();

        assertThat(HexEncoder.getString(r), is(
                "21655b5f1aa965996b3f97b3c849eafb" +
                        "a922a0a62992f73b3d1b73106a84ad85"));
        assertThat(HexEncoder.getString(s), is(
                "e9b86a7b6005ea868337ff2d20a7f5fb" +
                        "d4cd10b0be49a68da2b2e0dc0ad8960f"));
    }
}
