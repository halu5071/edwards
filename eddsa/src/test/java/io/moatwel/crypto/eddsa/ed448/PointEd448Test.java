package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class PointEd448Test {

    private Curve curve = Ed448Curve.getCurve();

    @Test
    public void success_ClonePoint() {
        Point point = curve.getBasePoint();
        Point refCopy = point;
        Point valCopy = point.clone();

        assertEquals(point, refCopy);
        assertNotEquals(point, valCopy);
    }
}
