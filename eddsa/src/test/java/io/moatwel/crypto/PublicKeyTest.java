package io.moatwel.crypto;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class PublicKeyTest {

    @Test
    public void success_GeneratePublicKey_from_HexString1() {
        String hexString = "1fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881";

        PublicKey publicKey = new PublicKey(HexEncoder.getBytes(hexString));

        assertThat(HexEncoder.getString(publicKey.getRaw()), is(hexString));
    }

    @Test
    public void success_GeneratePublicKey_from_HexString2() {
        String hexString = "1fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881";

        PublicKey publicKey = PublicKey.fromHexString(hexString);

        assertThat(HexEncoder.getString(publicKey.getRaw()), is(hexString));
        assertThat(publicKey.getHexString(), is(hexString));
    }

    @Test(expected = RuntimeException.class)
    public void failure_GeneratePublicKey_wrong_input() {
        String hexString = "abcdefgg";
        PublicKey.fromHexString(hexString);
    }

    @Test
    public void success_GeneratePublicKey_from_BigInteger() {
        BigInteger integer = new BigInteger("12345678990");
        PublicKey publicKey = new PublicKey(integer);

        assertThat(publicKey.getRaw(), is(integer.toByteArray()));
    }
}
