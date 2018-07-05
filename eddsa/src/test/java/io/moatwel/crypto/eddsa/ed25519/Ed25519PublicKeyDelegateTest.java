package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class Ed25519PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new Ed25519PublicKeyDelegate(HashAlgorithm.KECCAK_512);
    private Curve curve = Ed25519Curve.getCurve();

    @Test
    public void success_GeneratePublicKeySeed() {
        PrivateKey privateKey = new PrivateKey(new byte[32]);

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        byte[] value = new byte[]{70, 46, -23, 118, -119, 9, 22, -27, 79, -88, 37, -46, 107,
                -35, 2, 53, -11, -21, 91, 106, 20, 60, 25, -102, -80, -82, 94, -23, 50, -114, 8, -50};

        assertThat(HexEncoder.getString(value), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
        assertThat(seed, is(value));
        assertThat(HexEncoder.getString(seed), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
    }

    @Test
    public void measure_GeneratePublicKeySeed_ed25519() {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[32];

        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            random.nextBytes(seed);
            PrivateKey privateKey = new PrivateKey(seed);

            byte[] pubSeed = delegate.generatePublicKeySeed(privateKey);

            assertNotNull(pubSeed);
        }
        long end = System.currentTimeMillis();

        System.out.println("Measure: Generate PublicKey seed: " + (end - start) / 10000.0 + " ms");
    }

    @Test
    public void success_GenerateScalarA() {
        PrivateKey privateKey = new PrivateKey(new byte[32]);
        byte[] h = Hashes.hash(HashAlgorithm.SHA_512, privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        assertThat(s, is(new BigInteger("39325648866980652792715009169219496062012184734522019333892538943312776480336")));
    }
}
