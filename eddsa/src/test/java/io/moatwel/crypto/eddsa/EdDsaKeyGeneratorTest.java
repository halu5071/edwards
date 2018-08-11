package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.*;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EdDsaKeyGeneratorTest {

    private KeyGenerator generator;
    private KeyGenerator generator2;

    @Before
    public void setup() {
        generator = new Edwards().getKeyGenerator();
        generator2 = new Edwards(HashAlgorithm.SHA3_512).getKeyGenerator();
    }

    @Test
    public void success_GeneratePublicKey_from_all_zero_byte32() {
        long start = System.currentTimeMillis();
        byte[] seed = new byte[32];
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(seed);
        PublicKey publicKey = generator.derivePublicKey(privateKey);
        long end = System.currentTimeMillis();

        System.out.println("Measure: Generate PublicKey: " + (double) (end - start) + " ms");
        assertThat(publicKey.getHexString(), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
    }

    @Test
    public void generate() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("cdf762a91a9932fe755d1e62e1eabf94111d3fe9eafc191fe9cbedbd0902252c");
        PublicKey publicKey = generator2.derivePublicKey(privateKey);

        assertThat(publicKey.getHexString(), is("18c484505c8f175bbdd511acde1faaea8e35a579cfc0d220f6d3513ebb4204b5"));
    }

    @Test
    public void measure_GeneratePublicKey() {
        long start = System.currentTimeMillis();
        for (int i = 0; i < 2000; i++) {
            KeyPair pair = generator.generateKeyPair();
        }
        long end = System.currentTimeMillis();

        System.out.println("Measure: Generate PublicKey: " + (end - start) / 2000.0 + " ms");
    }
}
