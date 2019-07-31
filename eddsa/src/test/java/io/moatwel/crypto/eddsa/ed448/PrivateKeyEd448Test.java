package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.PrivateKey;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class PrivateKeyEd448Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length_1() {
        PrivateKey.newInstance(new byte[56]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length_2() {
        PrivateKey.newInstance(new byte[58]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length_3() {
        PrivateKey.newInstance("a8b41c2d013234");
    }

    @Test
    public void success_GeneratePrivateKey() {
        byte[] seed = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56};
        PrivateKey privateKey = PrivateKey.newInstance(seed);

        assertThat(privateKey.getRaw(), is(seed));
    }
}
