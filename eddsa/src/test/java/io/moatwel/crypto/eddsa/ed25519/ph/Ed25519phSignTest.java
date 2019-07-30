package io.moatwel.crypto.eddsa.ed25519.ph;

import io.moatwel.crypto.*;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Signer;
import io.moatwel.util.HexEncoder;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519phSignTest {

    private Edwards edwards;
    private EdDsaSigner signer = new Ed25519Signer(HashAlgorithm.SHA_512, new Ed25519phSchemeProvider(HashAlgorithm.SHA_512));

    @Before
    public void setup() {
        edwards = new Edwards(new Ed25519phSchemeProvider(HashAlgorithm.SHA_512));
    }

    @Test
    public void success_SignMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"));

        byte[] message = HexEncoder.getBytes("616263");
        Signature signature = signer.sign(keyPair, message, null);

        byte[] r = signature.getR();
        byte[] s = signature.getS();

        assertThat(HexEncoder.getString(r), is(
                "98a70222f0b8121aa9d30f813d683f80" +
                        "9e462b469c7ff87639499bb94e6dae41"));
        assertThat(HexEncoder.getString(s), is(
                "31f85042463c2a355a2003d062adf5aa" +
                        "a10b8c61e636062aaad11c2a26083406"));
    }
}
