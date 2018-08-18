package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;
import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class PrivateKeyEd25519Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length() {
        PrivateKey.newInstance(new byte[31]);
        PrivateKey.newInstance(new byte[33]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_hex_string() {
        PrivateKey.newInstance("98fa9d87f89ad7f");
    }

    @Test
    public void success_GeneratePrivateKey_from_all_zero_byte_array() {
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(new byte[32]);
        assertThat(privateKey.getInteger(), is(new BigInteger(1, new byte[32])));
        assertThat(privateKey.getInteger(), is(new BigInteger("00")));
        assertThat(privateKey.getRaw(), is(ByteUtils.paddingZeroOnHead(new BigInteger("00").toByteArray(), 32)));
    }

    @Test
    public void success_GeneratePrivateKey_from_hexString() {
        String hexStr = "ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487";
        byte[] result = HexEncoder.getBytes(hexStr);

        assertThat(result.length, is(32));
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString(hexStr);

        byte[] raw = privateKey.getRaw();

        assertThat(raw, is(result));
    }

    @Test
    public void success_GeneratePrivateKey_from_bytes() {
        byte[] seed = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        PrivateKey privateKey1 = PrivateKeyEd25519.fromBytes(seed);

        assertThat(privateKey1.getRaw(), is(seed));
    }

    @Test
    public void success_GeneratePrivateKey_from_random() {
        PrivateKey privateKey = PrivateKeyEd25519.random();

        assertNotNull(privateKey);
    }

    @Test
    public void success_SameByteArray_1() {
        byte[] seed = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        PrivateKey privateKey1 = PrivateKeyEd25519.fromBytes(seed);

        assertThat(privateKey1.getRaw(), is(seed));
    }
}
