package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;
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
        generator = new Edwards.Builder().curve(Ed25519Curve.getCurve()).build().getKeyGenerator();
    }

    @Test
    public void success_GeneratePublicKey_from_all_zero_byte32() {
        long start = System.currentTimeMillis();
        byte[] seed = new byte[32];
        PrivateKey privateKey = new PrivateKey(seed);

        PublicKey publicKey = generator.derivePublicKey(privateKey);
        long end = System.currentTimeMillis();
        System.out.println("Generate PublicKey: " + (double)(end - start) + " ms");
        assertThat(publicKey.getHexString(), is("b2ab021789401c61b988459c43239b03a31dc6ee1e2718a7b369667ea0270b1e"));
    }

    @Test
    public void success_MeasureGeneratePublicKey() {
        long start = System.currentTimeMillis();

        for (int i = 1; i <= 1000; i++) {
            byte[] seed = new byte[32];
            PrivateKey privateKey = new PrivateKey(seed);
            PublicKey publicKey = generator.derivePublicKey(privateKey);
        }

        long end = System.currentTimeMillis();

        double average = (end - start) / 1000d;
        System.out.println("====== Generated PublicKey ======");
        System.out.println("ave: " + average + " ms");
    }
}
