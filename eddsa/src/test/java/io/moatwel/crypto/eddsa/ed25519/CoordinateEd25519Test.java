package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;

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

    @Test
    public void success_DivideCoordinate() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("1000"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("2"));

        Coordinate result = coordinate1.divide(coordinate2);

        assertEquals(result.getInteger(), new BigInteger("500"));
    }

    @Test
    public void success_MultiplyCoordinate() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("1000"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("2"));

        Coordinate result = coordinate1.multiply(coordinate2);

        assertEquals(result.getInteger(), new BigInteger("2000"));
    }

    @Test
    public void success_InverseCoordinate() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("100"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("101241240"));

        Coordinate result1 = coordinate1.inverse();
        Coordinate result2 = coordinate2.inverse();

        assertThat(result1.getInteger(), is(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174")));
        assertThat(result2.getInteger(), is(new BigInteger("38867791596533294917564303539771571723867178851912571219685671691706937241210")));
    }

    @Test
    public void success_SomeOperation() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("1000"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("2"));
        Coordinate coordinate3 = new CoordinateEd25519(new BigInteger("4"));
        Coordinate coordinate4 = new CoordinateEd25519(new BigInteger("14"));

        Coordinate result = coordinate1.add(coordinate3).multiply(coordinate2);
        Coordinate result2 = coordinate2.multiply(coordinate3).add(coordinate1);
        Coordinate result3 = coordinate3.add(coordinate4).add(coordinate1).multiply(coordinate2);

        assertThat(result.getInteger(), is(new BigInteger("2008")));
        assertThat(result2.getInteger(), is(new BigInteger("1008")));
        assertThat(result3.getInteger(), is(new BigInteger("2036")));
    }
}
