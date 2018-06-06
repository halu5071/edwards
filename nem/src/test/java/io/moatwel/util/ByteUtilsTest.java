package io.moatwel.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class ByteUtilsTest {

    @Test
    public void success_SplitByteArray() {
        byte[] input = new byte[]{32, 43, 53, 56, 34, 23, 43, 93, 42, 42};
        byte[][] result = ByteUtils.split(input, 5);

        assertThat(result[0], is(new byte[]{32, 43, 53, 56, 34}));
        assertThat(result[1], is(new byte[]{23, 43, 93, 42, 42}));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void failure_SplitByteArray() {
        byte[] input = new byte[]{32, 43, 53, 56, 34, 23, 43};
        ByteUtils.split(input, 8);
    }

    @Test
    public void success_LittleEndianInteger() {
        byte[] input = new byte[]{26, 94, 11, 65, 43, 13, 62, 53, 13, 43};
        assertThat(ByteUtils.getLittleEndianInteger(input), is(new BigInteger("124516333474283255041323")));
    }
}
