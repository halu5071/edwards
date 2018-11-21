package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class EdwardsTest {

    private Edwards edwards;

    @Before
    public void setup() {
        edwards = new Edwards(HashAlgorithm.SHA_512);
    }

    @Test(expected = NullPointerException.class)
    public void failure_InstantiateEdwards() {
        SchemeProvider provider = null;
        new Edwards(provider);
    }

    @Test
    public void success_GeneratePublicKey() {
        byte[] privateKeySeed = new byte[]{42, 52, 74, 1, 6, -34, 13, 64, 83, 21, 34, -3, -7, 41, 92, 38, 43, 77, 21, -91, 23, 11, 84, 34, 98, 28, 44, 54, 123, -123, 34, 55};
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(privateKeySeed);

        PublicKey publicKey = edwards.derivePublicKey(privateKey);
        assertNotNull(publicKey);
    }

    @Test
    public void success_GenerateKeyPair() {
        byte[] privateKeySeed = new byte[]{42, 52, 74, 1, 6, -34, 13, 64, 83, 21, 34, -3, -7, 41, 92, 38, 43, 77, 21, -91, 23, 11, 84, 34, 98, 28, 44, 54, 123, -123, 34, 55};
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(privateKeySeed);

        KeyPair pair = edwards.generateKeyPair(privateKey);
        assertNotNull(pair);

        assertThat(pair.getPrivateKey(), is(privateKey));
    }

    @Test
    public void success_GetCurve() {
        Curve curve = edwards.getCurve();
        assertEquals(curve, Curve25519.getInstance());
    }
}
