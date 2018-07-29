package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.ed448.CoordinateEd448;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class CoordinateEd25519Test {

    @Test
    public void success_GenerateCoordinate_byte_array_length_32() {
        BigInteger integer = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        assertThat(integer.toByteArray().length, is(32));
        Coordinate coordinate = new CoordinateEd25519(integer);

        assertNotNull(coordinate);
        assertThat(coordinate.getInteger().toByteArray().length, is(32));
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
        Coordinate coordinate5 = new CoordinateEd25519(new BigInteger("-1"));

        Coordinate result = coordinate1.add(coordinate3).multiply(coordinate2).mod();
        Coordinate result2 = coordinate2.multiply(coordinate3).add(coordinate1).mod();
        Coordinate result3 = coordinate2.multiply(coordinate1).subtract(coordinate4).mod();
        Coordinate result4 = coordinate3.add(coordinate4).add(coordinate1).multiply(coordinate2).mod();
        Coordinate result5 = coordinate2.multiply(coordinate1).subtract(coordinate2.multiply(coordinate4)).mod();
        Coordinate result6 = coordinate5.multiply(coordinate1);

        assertThat(result.getInteger(), is(new BigInteger("2008")));
        assertThat(result2.getInteger(), is(new BigInteger("1008")));
        assertThat(result3.getInteger(), is(new BigInteger("1986")));
        assertThat(result4.getInteger(), is(new BigInteger("2036")));
        assertThat(result5.getInteger(), is(new BigInteger("1972")));

        assertThat(coordinate5.getInteger(), is(BigInteger.ONE.negate()));
        assertThat(result6.getInteger(), is(new BigInteger("-1000")));
    }

    @Test
    public void success_IsEqual_true_1() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));

        assertThat(coordinate1.isEqual(coordinate2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Coordinate coordinate1 = new CoordinateEd25519(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("84412282755515629833010601177215416502583846089738343830061683922017848058174"));

        assertThat(coordinate1.isEqual(coordinate2), is(false));
    }

    @Test(expected = RuntimeException.class)
    public void failure_IsEqual_different_implementation() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));
        Coordinate coordinate2 = new CoordinateEd25519(new BigInteger("84412282755515629833010601177215416502583846089738343830061683922017848058174"));

        coordinate1.isEqual(coordinate2);
    }
}