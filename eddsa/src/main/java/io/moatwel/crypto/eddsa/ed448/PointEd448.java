package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;

import java.math.BigInteger;

public class PointEd448 extends Point {

    private static final Point ZERO =
            new PointEd448(new CoordinateEd448(BigInteger.ZERO), new CoordinateEd448(BigInteger.ZERO));

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public PointEd448(Coordinate x, Coordinate y) {
        super(x, y);
        curve = Curve448.getInstance();

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point add(Point point) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point scalarMultiply(BigInteger integer) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public EncodedPoint encode() {
        return null;
    }
}
