package io.moatwel.util;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class HexEncoderTest {

    @Test
    public void success_GetString_from_byte() {
        byte[] input = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        String hex = HexEncoder.getString(input);

        assertThat(hex, is("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        assertThat(HexEncoder.getBytes(hex), is(input));
    }

    @Test
    public void success_GetString_from_hexString() {
        String hex = "abcd12";

        byte[] result = HexEncoder.getBytes(hex);

        assertThat(result, is(new byte[]{-85, -51, 18}));
        assertThat(HexEncoder.getString(result), is("abcd12"));
    }
}
