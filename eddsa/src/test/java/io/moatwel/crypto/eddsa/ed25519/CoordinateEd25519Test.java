package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.ed25519.CoordinateEd25519;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Coordinate.class)
public class CoordinateEd25519Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateCoordinate_wrong_byte_array_length() {
        new CoordinateEd25519(new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateCoordinate_bigger_byte_array_length() {
        new CoordinateEd25519(new byte[33]);
    }

    @Test
    public void success_GenerateCoordinate_bigInteger_less_than_32_byte_length() {
        BigInteger integer = new BigInteger("1");
        Coordinate coordinate = new CoordinateEd25519(integer);

        assertNotNull(coordinate);
        assertEquals(coordinate.getValue().length, 32);
    }

    @Test
    public void success_GenerateCoordinate_byte_array_length_32() {
        BigInteger integer = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        assertThat(integer.toByteArray().length, is(32));
        Coordinate coordinate = new CoordinateEd25519(integer);

        assertNotNull(coordinate);
        assertThat(coordinate.getValue().length, is(32));
    }

    @Test
    public void success_AddCoordinate() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("1"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("2"));

        Coordinate result = coordinate1.add(coordinate2);

        assertEquals(result.getInteger(), new BigInteger("3"));
    }
}
