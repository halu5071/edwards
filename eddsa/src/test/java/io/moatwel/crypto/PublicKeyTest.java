package io.moatwel.crypto;

import io.moatwel.util.HexEncoder;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class PublicKeyTest {

    @Test
    public void success_GeneratePublicKey() {
        String hexString = "1fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881";

        PublicKey publicKey = new PublicKey(HexEncoder.getBytes(hexString));

        assertThat(HexEncoder.getString(publicKey.getRaw()), is(hexString));
    }
}
