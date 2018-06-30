package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;
import io.moatwel.util.ByteUtils;

/**
 * A point on the eddsa curve which represents a group of {@link Coordinate}.
 */
public class Point {

    private final Coordinate x;
    private final Coordinate y;

    // TODO: make this class abstract
    private final Curve curve = Ed25519Curve.getCurve();

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

    public Point add(Point point) {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate x2 = point.getX();
        Coordinate y2 = point.getY();

        // TODO: add d which is on curve.
        Coordinate x3 = x1.multiply(y2).add(x2.multiply(y1)).multiply(Coordinate.ONE.add(x1.multiply(x2).multiply(y1).multiply(y2)));

        return null;
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
