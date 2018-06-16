package io.moatwel.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

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
}
