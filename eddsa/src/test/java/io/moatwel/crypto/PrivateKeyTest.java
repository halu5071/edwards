package io.moatwel.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Ed25519PublicKeyDelegate;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class PrivateKeyTest {

    @Test
    public void success_GeneratePrivateKey_from_all_zero_byte_array() {
        PrivateKey privateKey = PrivateKey.fromBytes(new byte[32]);
        assertThat(privateKey.getInteger(), is(new BigInteger(1, new byte[32])));
        assertThat(privateKey.getInteger(), is(new BigInteger("00")));
        assertThat(privateKey.getRaw(), is(new BigInteger("00").toByteArray()));
    }

    @Test
    public void success_GeneratePrivateKey_from_hexString() {
        String hexStr = "ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487";
        byte[] result = HexEncoder.getBytes(hexStr);

        assertThat(result.length, is(32));
        PrivateKey privateKey = PrivateKey.fromHexString(hexStr);

        byte[] raw = privateKey.getRaw();

        assertThat(raw, is(result));
    }

    @Test
    public void success_GeneratePrivateKey_from_bytes() {
        byte[] seed = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        BigInteger integer = new BigInteger(1, seed);
        PrivateKey privateKey1 = PrivateKey.fromBytes(seed);
        PrivateKey privateKey2 = PrivateKey.fromBigInteger(integer);

        assertThat(privateKey1.getRaw(), is(seed));
        assertThat(privateKey2.getRaw(), is(seed));
    }

    @Test
    public void success_GeneratePrivateKey_from_BigInteger() {
        BigInteger integer = new BigInteger("24727413235106541002554574571675588834622768167397638456726423682521233608206");
        byte[] bInteger = integer.toByteArray();

        PrivateKey privateKey = PrivateKey.fromBigInteger(integer);

        assertThat(privateKey.getRaw(), is(bInteger));
    }
}
