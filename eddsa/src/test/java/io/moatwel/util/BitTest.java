package io.moatwel.util;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class BitTest {

    @Test
    public void clear_the_lowest_3_bits() {
        byte value1 = 0b01011101;
        byte value2 = 0b01011011;
        byte value3 = 0b01111111;
        byte value4 = 0b01000010;

        value1 &= 0xF8;
        value2 &= 0xF8;
        value3 &= 0xF8;
        value4 &= 0xF8;

        assertThat(value1, is((byte) 0b01011000));
        assertThat(value2, is((byte) 0b01011000));
        assertThat(value3, is((byte) 0b01111000));
        assertThat(value4, is((byte) 0b01000000));
    }

    @Test
    public void clear_the_last_bit() {
        byte value1 = 0b01011101;
        byte value2 = 0b01011011;
        byte value3 = 0b01111111;
        byte value4 = 0b01000010;

        value1 &= 0xFE;
        value2 &= 0xFE;
        value3 &= 0xFE;
        value4 &= 0xFE;

        assertThat(value1, is((byte) 0b01011100));
        assertThat(value2, is((byte) 0b01011010));
        assertThat(value3, is((byte) 0b01111110));
        assertThat(value4, is((byte) 0b01000010));
    }

    @Test
    public void set_the_second_highest_bit() {
        byte value1 = 0b00011101;
        byte value2 = 0b01011011;
        byte value3 = 0b00111101;
        byte value4 = 0b01010010;
        byte value5 = 0b00111101;
        byte value6 = 0b00010010;

        value1 &= 0x7F;
        value1 |= 0x40;

        value2 &= 0x7F;
        value2 |= 0x40;

        value3 &= 0x7F;
        value3 |= 0x40;

        value4 &= 0x7F;
        value4 |= 0x40;

        value5 &= 0x7F;
        value5 |= 0x40;

        value6 &= 0x7F;
        value6 |= 0x40;

        assertThat(value1, is((byte) 0b01011101));
        assertThat(value2, is((byte) 0b01011011));
        assertThat(value3, is((byte) 0b01111101));
        assertThat(value4, is((byte) 0b01010010));
        assertThat(value5, is((byte) 0b01111101));
        assertThat(value6, is((byte) 0b01010010));
    }

    @Test
    public void read_bit() {
        byte value = 0b01010101;
        int read = value & 0b00000001;
        int read2 = value & 0b00001000;
        int read3 = value & 0b10000000;

        assertThat(read, is(1));
        assertThat(read2, is(0));
        assertThat(read3, is(0));
    }

    @Test
    public void write_bit() {
        byte value = 0b00000000;
        int writeBit = 1;
        value |= writeBit;
        assertThat(value, is(((byte) 0b00000001)));

        byte value2 = 0b01111111;
        int writeBit2 = ~(1 << 4);
        value2 &= writeBit2;
        assertThat(value2, is(((byte) 0b01101111)));
        writeBit2 = ~(1);
        value2 &= writeBit2;
        assertThat(value2, is(((byte) 0b01101110)));
    }
}
