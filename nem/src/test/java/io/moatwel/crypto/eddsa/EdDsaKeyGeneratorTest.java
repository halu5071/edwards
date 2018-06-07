package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.CryptoProvider;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.util.ByteUtils;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(value = {Curve.class, CryptoProvider.class})
public class EdDsaKeyGeneratorTest {

    private KeyGenerator generator;
    private Curve curve;
    private CryptoProvider provider;

    @Before
    public void setup() {
        curve = mock(Curve.class);
        provider = mock(CryptoProvider.class);
        generator = new EdDsaKeyGenerator(curve, provider);
    }

//    @Test
//    public void success_GeneratePublicKey() {
//        byte[] seed = new byte[];
//        PrivateKey privateKey = new PrivateKey(seed);
//    }

    @Test
    public void success_ClearLowestThreeBits_of_the_first_octet() {
        byte val1 = (byte) 103;
        byte val2 = (byte) 90;
        val1 &= 0xF8;
        val2 &= 0xF8;

        assertThat(val1, is((byte) 96));
        assertThat(val2, is((byte) 88));
    }

    @Test
    public void success_SetSecondHighestBit_of_the_last_octet() {
        byte val1 = (byte) 54;
        byte val2 = (byte) 182;
        byte val3 = (byte) 118;
        byte val4 = (byte) 246;

        val1 |= 0b1000000;
        val1 = (byte)(val1 & ~(1 << 8));

        val2 |= 0b1000000;
        val2 = (byte)(val1 & ~(1 << 8));

        val3 |= 0b1000000;
        val3 = (byte)(val1 & ~(1 << 8));

        val4 |= 0b1000000;
        val4 = (byte)(val1 & ~(1 << 8));

        assertThat(val1, is((byte) 118));
        assertThat(val2, is((byte) 118));
        assertThat(val3, is((byte) 118));
        assertThat(val4, is((byte) 118));
    }
}
