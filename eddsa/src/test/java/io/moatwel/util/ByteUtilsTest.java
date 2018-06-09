package io.moatwel.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

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
    public void success_reverse() {
        byte[] input = new byte[]{26, 94, 11, 65, 43, 13, 62, 53, 13, 43};
        assertThat(ByteUtils.reverse(input), is(new byte[]{43, 13, 53, 62, 13, 43, 65, 11, 94, 26}));
        byte[] input2 = new byte[]{54, 25, 53, 91, 24, 42, 51, 51, 54, 41, 35, 30, 45, 14, 34, 53};
        assertThat(ByteUtils.reverse(input2), is(new byte[]{53, 34, 14, 45, 30, 35, 41, 54, 51, 51, 42, 24, 91, 53, 25, 54}));
    }

    @Test
    public void success_JoinByteArray() {
        byte[] input1 = new byte[]{1, 2, 3, 4, 5};
        byte[] input2 = new byte[]{6, 7, 8, 9, 10};

        byte[] result = ByteUtils.join(input1, input2);

        assertThat(result, is(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
    }
}
