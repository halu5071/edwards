package io.moatwel.crypto.eddsa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.ed25519.CoordinateEd25519;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Coordinate.class)
public class CoordinateEd25519Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateCoordinate_wrong_byte_array_length() {
        new CoordinateEd25519(new byte[31]);
    }

    @Test
    public void success_GenerateCoordinate_byte_array_length_32() {
        BigInteger integer = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        assertThat(integer.toByteArray().length, is(32));
        Coordinate coordinate = new CoordinateEd25519(integer);

        assertNotNull(coordinate);
        assertThat(coordinate.getValue().length, is(32));
    }
}
