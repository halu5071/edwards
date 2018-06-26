package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;

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
        PrivateKey privateKey = new PrivateKey(seed);
        PublicKey publicKey = generator.derivePublicKey(privateKey);
        long end = System.currentTimeMillis();

        System.out.println("Generate PublicKey: " + (double)(end - start) + " ms");
        assertThat(publicKey.getHexString(), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));

        byte[] seed2 = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        PrivateKey privateKey2 = new PrivateKey(seed2);
        PublicKey publicKey2 = generator.derivePublicKey(privateKey2);
        assertThat(publicKey2.getHexString(), is("1d8507094afcc34d019ed2f064e58f0840eb837ac406ac92bafe48b9cd68b893"));
    }

    @Test
    public void success_MeasureGeneratePublicKey() {
        long start = System.currentTimeMillis();

        for (int i = 1; i <= 1000; i++) {
            byte[] seed = new byte[32];
            PrivateKey privateKey = PrivateKey.fromBytes(seed);
            PublicKey publicKey = generator.derivePublicKey(privateKey);
        }

        long end = System.currentTimeMillis();

        double average = (end - start) / 1000d;
        System.out.println("====== Generated PublicKey ======");
        System.out.println("ave: " + average + " ms");
    }
}
