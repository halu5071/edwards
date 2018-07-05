package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.ed25519.CoordinateEd25519;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;
import io.moatwel.crypto.eddsa.ed25519.PointEd25519;
import io.moatwel.util.ByteUtils;

/**
 * A point on the eddsa curve which represents a group of {@link Coordinate}.
 */
public abstract class Point {

    protected final Coordinate x;
    protected final Coordinate y;

    protected static Curve curve;

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

    public abstract Point add(Point point);

    public abstract Point scalarMultiply(BigInteger integer);

    public EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(y.getInteger().toByteArray());
        int lengthX = x.getInteger().toByteArray().length;
        int lengthY = reversedY.length;
        int writeBit = x.getInteger().toByteArray()[lengthX - 1] & 1;
        reversedY[lengthY - 1] |= writeBit;

        return new EncodedPoint(reversedY);
    }
}
