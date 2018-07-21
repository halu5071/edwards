package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class EdDsaKeyGeneratorTest {

    private KeyGenerator generator;

    @Before
    public void setup() {
        generator = new Edwards().getKeyGenerator();
    }

    @Test
    public void success_GeneratePublicKey_from_all_zero_byte32() {
        long start = System.currentTimeMillis();
        byte[] seed = new byte[32];
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(seed);
        PublicKey publicKey = generator.derivePublicKey(privateKey);
        long end = System.currentTimeMillis();

        System.out.println("Measure: Generate PublicKey: " + (double)(end - start) + " ms");
        assertThat(publicKey.getHexString(), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
    }
}
