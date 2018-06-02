package io.moatwel.crypto.eddsa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Coordinate.class)
public class CoordinateTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateCoordinate_wrong_byte_array_length() {
        new Coordinate(new byte[31]);
        new Coordinate(new byte[53]);
    }

    @Test
    public void success_GenerateCoordinate_byte_array_length_56() {
        BigInteger integer = new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710");
        assertThat(integer.toByteArray().length, is(56));
        Coordinate coordinate = new Coordinate(integer);

        assertNotNull(coordinate);
        assertThat(coordinate.getValue().length, is(56));
    }

    @Test
    public void success_GenerateCoordinate_byte_array_length_32() {
        BigInteger integer = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        assertThat(integer.toByteArray().length, is(32));
        Coordinate coordinate = new Coordinate(integer);

        assertNotNull(coordinate);
        assertThat(coordinate.getValue().length, is(32));
    }
}
