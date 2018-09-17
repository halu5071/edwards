package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;

public class PointEd448Test {

    private Curve curve = Curve448.getInstance();

    @Test
    public void success_ClonePoint() {
        Point point = curve.getBasePoint();
        Point refCopy = point;
        Point valCopy = point.clone();

        assertEquals(point, refCopy);
        assertNotEquals(point, valCopy);
    }

    @Test
    public void success_IsEqual_true_1() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("112345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_2() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("223456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_3() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("112345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_4() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("223456")));

        assertThat(point1.isEqual(point2), is(false));
    }
}
