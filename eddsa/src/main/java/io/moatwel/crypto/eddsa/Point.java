package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.ed25519.PointEd25519;

/**
 * A point on the eddsa curve which represents a group of {@link Coordinate}.
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/2
 * @see PointEd25519
 * @see io.moatwel.crypto.eddsa.ed448.PointEd448
 */
public abstract class Point implements Cloneable {

    protected Coordinate x;
    protected Coordinate y;

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

    /**
     * Point on edwards curve can be added. However, it is not just an addition like
     * {@code int result = 1 + 1;} on elliptic curve.
     * <p>Addition of each coordinates are defined as follows.
     * <pre>
     * {@code
     *            x1 * y2 + x2 * y1                y1 * y2 - a * x1 * x2
     *  x3 = --------------------------,   y3 = ---------------------------
     *       1 + d * x1 * x2 * y1 * y2           1 - d * x1 * x2 * y1 * y2
     * }
     * </pre>
     * <p>A class extends this class must pay attention this addition.
     *
     * @param point which will be added.
     * @return {@link Point} will have been added.
     */
    public abstract Point add(Point point);

    /**
     * Point on edwards curve can be multiplied. However, it is not just a multiplication like
     * {@code int result = 10 * 3;} on elliptic curve.
     * <p>
     * A multiplication on elliptic curve is defined as a lot of addition. However, just adding
     * spend a lot of time to calculate, so use 'double-and-add' algorithm or some others.
     * See also brief description of
     * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication">Elliptic curve point multiplication</a>
     *
     * @param integer scalar value to multiply Point.
     * @return {@link Point} which will be multiplied.
     */
    public abstract Point scalarMultiply(BigInteger integer);

    /**
     * All values on edwards curve are coded as octet strings.
     * <p>
     * Point can be encoded as follows.
     * <ul>
     * <li>First, encode the y-coordinate as a little-endian string. ths most significant bit
     * of the final octet is always zero.
     * <li>Second, copy the least significant bit of the x-coordinate to the most significant
     * bit of the final octet.
     * </ul>
     *
     * @return {@link EncodedPoint} on each edwards curve.
     */
    public abstract EncodedPoint encode();

    /**
     * Check value equality between two Points.
     * <p>Pay attention not to check different Point implementation. Below code will throw
     * RuntimeException.
     * <pre>
     *      {@code
     *          Point point1 = new PointEd25519(...);
     *          Point point2 = new PointEd448(...);
     *          point1.isEqual(point2);
     *      }
     * </pre>
     *
     * @param point target {@link Point} to check value.
     * @return true, if both Points have {@link Coordinate}s which have the same value each.
     * false, others.
     * @throws RuntimeException when you check different Point implementations.
     */
    public boolean isEqual(Point point) {
        if (point.getClass() != this.getClass()) {
            throw new RuntimeException("These points can not be compared. Different point implementation.");
        }

        return point.getX().isEqual(this.x) && point.getY().isEqual(this.y);
    }

    @Override
    public Point clone() {
        Point point = null;

        try {
            point = ((Point) super.clone());
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
        }

        if (point != null) {
            point.x = x.clone();
            point.y = y.clone();
        }

        return point;
    }
}
