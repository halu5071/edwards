package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import io.moatwel.crypto.eddsa.ed448.Ed448SchemeProvider;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class EdDsaKeyGeneratorTest {

    private KeyGenerator generator;
    private KeyGenerator generator2;

    @Before
    public void setup() {
        generator = Edwards.newInstance().getKeyGenerator();
        generator2 = Edwards.newInstance(HashAlgorithm.SHA3_512).getKeyGenerator();
    }

    @Test
    public void success_GeneratePublicKey_from_all_zero_byte32() {
        byte[] seed = new byte[32];
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(seed);
        PublicKey publicKey = generator.derivePublicKey(privateKey);

        assertThat(publicKey.getHexString(), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
    }

    @Test
    public void generate() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("cdf762a91a9932fe755d1e62e1eabf94111d3fe9eafc191fe9cbedbd0902252c");
        PublicKey publicKey = generator2.derivePublicKey(privateKey);

        assertThat(publicKey.getHexString(), is("18c484505c8f175bbdd511acde1faaea8e35a579cfc0d220f6d3513ebb4204b5"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateKeyGenerator() {
        new EdDsaKeyGenerator(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePublicKey_Curve25519() {
        KeyGenerator generator = Edwards.newInstance().getKeyGenerator();
        generator.derivePublicKey(null);
    }

    @Test
    public void success_GenerateKeyPair_Curve25519() {
        KeyGenerator generator = Edwards.newInstance().getKeyGenerator();
        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @Test
    public void success_GetKeyAnalyzer_Curve25519() {
        KeyGenerator generator = Edwards.newInstance().getKeyGenerator();
        EdKeyAnalyzer analyzer = generator.getKeyAnalyzer();

        assertNotNull(analyzer);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePublicKey_Curve448() {
        SchemeProvider schemeProvider = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);
        KeyGenerator generator = Edwards.newInstance(schemeProvider).getKeyGenerator();
        generator.derivePublicKey(null);
    }

    @Test
    public void success_GenerateKeyPair_Curve448() {
        SchemeProvider schemeProvider = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);
        KeyGenerator generator = Edwards.newInstance(schemeProvider).getKeyGenerator();
        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @Test
    public void success_GetKeyAnalyzer_Curve448() {
        SchemeProvider schemeProvider = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);
        KeyGenerator generator = Edwards.newInstance(schemeProvider).getKeyGenerator();
        EdKeyAnalyzer analyzer = generator.getKeyAnalyzer();

        assertNotNull(analyzer);
    }
}
