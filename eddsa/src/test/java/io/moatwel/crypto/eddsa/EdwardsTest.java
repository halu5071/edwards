package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.SecureRandom;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

@RunWith(PowerMockRunner.class)
public class EdwardsTest {

    private Edwards edwards;

    @Before
    public void setup() {
        edwards = new Edwards();
    }

    @Test
    public void success_Sign() {
        KeyPair pair = edwards.generateKeyPair();
        Signature signature = edwards.sign(pair, new byte[32]);
        System.out.println("r: " + signature.getR() + " s: " + signature.getS());
    }

    @Test
    public void success_Sign_measure() {
        KeyPair pair = edwards.generateKeyPair();
        SecureRandom random = new SecureRandom();
        byte[] input = new byte[32];

        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            random.nextBytes(input);
            Signature signature = edwards.sign(pair, input);
        }
        long end = System.currentTimeMillis();

        System.out.println("Signing Time: " + (end - start) / 1000);
    }
}
