package io.moatwel.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.util.HexEncoder;

@RunWith(PowerMockRunner.class)
@PrepareForTest(PublicKey.class)
public class PublicKeyTest {

    @Test
    public void success_GeneratePublicKey() {
        String hexString = "1fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881";

        PublicKey publicKey = new PublicKey(HexEncoder.getBytes(hexString));

        assertThat(HexEncoder.getString(publicKey.getRaw()), is(hexString));
    }
}
