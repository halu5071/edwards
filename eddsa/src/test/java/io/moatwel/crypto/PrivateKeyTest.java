package io.moatwel.crypto;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import io.moatwel.crypto.eddsa.ed448.PrivateKeyEd448;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class PrivateKeyTest {

    private byte[] seed1 = new byte[32];
    private byte[] seed2 = new byte[57];

    @Before
    public void setup() {
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed1);
        random.nextBytes(seed2);
    }

    @Test
    public void success_GeneratePrivateKey_1() {
        PrivateKey privateKey1 = PrivateKey.newInstance(seed1);
        boolean isPrivateKey25519 = privateKey1 instanceof PrivateKeyEd25519;
        assertThat(isPrivateKey25519, is(true));
        assertThat(privateKey1.getRaw(), is(seed1));
        assertThat(privateKey1.getHexString(), is(HexEncoder.getString(seed1)));

        PrivateKey privateKey2 = PrivateKey.newInstance(seed2);
        boolean isPrivateKey448 = privateKey2 instanceof PrivateKeyEd448;
        assertThat(isPrivateKey448, is(true));
        assertThat(privateKey2.getRaw(), is(seed2));
        assertThat(privateKey2.getHexString(), is(HexEncoder.getString(seed2)));
    }

    @Test
    public void success_GeneratePrivateKey_2() {
        PrivateKey privateKey = PrivateKey.newInstance("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487");
        boolean isKey25519 = privateKey instanceof PrivateKeyEd25519;
        assertThat(isKey25519, is(true));
    }

    @Test
    public void success_GetBigInteger() {
        byte[] seed = HexEncoder.getBytes("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487");
        BigInteger integer = new BigInteger(1, seed);

        PrivateKey privateKey = PrivateKey.newInstance(seed);
        assertThat(privateKey.getInteger(), is(integer));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey() {
        PrivateKey.newInstance(new byte[56]);
        PrivateKey.newInstance(new byte[31]);
    }

    @Test
    public void success_IsEqual() {
        PrivateKey privateKey1 = PrivateKey.newInstance("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487");
        PrivateKey privateKey2 = PrivateKey.newInstance("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487");
        PrivateKey privateKey3 = PrivateKey.newInstance(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56});
        PublicKey publicKey = PublicKey.fromHexString("abcdef123");

        boolean isEqual = privateKey1.equals(privateKey2);
        boolean isEqual2 = privateKey1.equals(privateKey3);
        boolean isEqual3 = privateKey1.equals(publicKey);

        assertThat(isEqual, is(true));
        assertThat(isEqual2, is(false));
        assertThat(isEqual3, is(false));
    }

    @Test
    public void success_hashCode() {
        PrivateKey privateKey1 = PrivateKey.newInstance("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487");
        PrivateKey privateKey2 = PrivateKey.newInstance("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb486");

        assertNotEquals(privateKey1.hashCode(), privateKey2.hashCode());
    }
}
