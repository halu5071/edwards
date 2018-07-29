package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Before;
import org.junit.Test;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.HashProvider;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.DefaultHashProvider;
import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519VerifyTest {

    private KeyPair pair;
    private HashProvider sha512Provider = new DefaultHashProvider(HashAlgorithm.SHA_512);
    private EdDsaSigner signer = new Ed25519Signer(sha512Provider);

    @Before
    public void setup() {
        KeyGenerator generator = new EdDsaKeyGenerator(new Ed25519CurveProvider(sha512Provider));
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("abd3df0ba4c941a451c934a44938cc2bf051233c4e535931233c4e5351a4c695");
        pair = generator.generateKeyPair(privateKey);

        assertThat(pair.getPublicKey().getHexString(), is("195ac5d462f0aa357c424982250f994ab0918ecee50a2ce5c6feb4f6b07ab660"));
    }

    @Test
    public void success_VerifySignature_1() {
        System.out.println("Empty test: Ed25519VerifyTest");
    }
}
