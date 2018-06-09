package io.moatwel.crypto.eddsa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

@RunWith(PowerMockRunner.class)
public class EdwardsTest {

    @Test
    public void test() {
        Edwards edwards = new Edwards.Builder()
                .curve(Ed25519Curve.getCurve())
                .build();
        KeyPair pair = edwards.generateKeyPair();
        edwards.sign(pair, new byte[32]);
    }
}
