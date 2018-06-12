package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

import io.moatwel.util.ByteUtils;

/**
 * A point on the eddsa curve which represents a group of {@link Coordinate}.
 */
public class Point {

    //TODO implement Coordinate.ZERO, Coordinate.ONE
    public static final Point ZERO = new Point(Coordinate.ZERO, Coordinate.ONE);

    private final Coordinate x;
    private final Coordinate y;

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public Point(Coordinate x, Coordinate y) {
        this.x = x;
        this.y = y;
    }

    public Coordinate getX() {
        return x;
    }

    public Coordinate getY() {
        return y;
    }

    public Point scalarMultiply(BigInteger integer) {
        return null;
    }

    public EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(y.getValue());
        int lengthX = x.getValue().length;
        int lengthY = reversedY.length;
        int writeBit = x.getValue()[lengthX - 1] & 1;
        reversedY[lengthY - 1] |= writeBit;

        return new EncodedPoint(reversedY);
    }
}
