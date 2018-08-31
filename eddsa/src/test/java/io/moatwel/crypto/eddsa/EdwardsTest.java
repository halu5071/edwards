package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import org.junit.Before;
import org.junit.Test;

public class EdwardsTest {

    private Edwards edwards;

    @Before
    public void setup() {
        edwards = new Edwards(HashAlgorithm.SHA_512);
    }

    @Test
    public void test() {
        byte[] privateKeySeed = new byte[]{42, 52, 74, 1, 6, -34, 13, 64, 83, 21, 34, -3, -7, 41, 92, 38, 43, 77, 21, -91, 23, 11, 84, 34, 98, 28, 44, 54, 123, -123, 34, 55};
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(privateKeySeed);

        PublicKey publicKey = edwards.derivePublicKey(privateKey);
    }
}
