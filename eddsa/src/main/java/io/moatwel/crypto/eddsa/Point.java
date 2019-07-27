package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * A point on the eddsa curve which represents a group of {@link Coordinate}.
 * <p>
 * A subclass of this class must be immutable object, in other words, all operations
 * must create new object.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class Point {

    protected final Coordinate x;
    protected final Coordinate y;
    protected final Coordinate z;

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    protected Point(Coordinate x, Coordinate y, Coordinate z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    /**
     * Return x-coordinate value.
     *
     * @return x coordinate
     */
    public Coordinate getX() {
        return x;
    }

    public Coordinate getAffineX() {
        Coordinate zInverse = z.inverse();
        return x.multiply(zInverse).mod();
    }

    /**
     * Return y-coordinate value.
     *
     * @return y coordinate
     */
    public Coordinate getY() {
        return y;
    }

    public Coordinate getAffineY() {
        Coordinate zInverse = z.inverse();
        return y.multiply(zInverse).mod();
    }

    public Coordinate getZ() {
        return z;
    }

    /**
     * Return a Point which is result of addition of two points.
     *
     * <p>
     * Pay attention that addition on elliptic curve is not just an addition like
     * {@code int result = 1 + 1;}.
     * <p>Addition of each coordinates are defined as follows.
     * <pre>
     * {@code
     *            x1 * y2 + x2 * y1                y1 * y2 - a * x1 * x2
     *  x3 = --------------------------,   y3 = ---------------------------
     *       1 + d * x1 * x2 * y1 * y2           1 - d * x1 * x2 * y1 * y2
     * }
     * </pre>
     * <p>A class extends this class must pay attention to this addition.
     *
     * @param point which will be added.
     * @return {@link Point} will have been added.
     */
    public abstract Point add(Point point);

    /**
     * Return a Point which is result of doubling of a point.
     *
     * You know, of course the result of addition between each other is the same
     * as a return of this. But there is some optimization for doubling.
     *
     * @return {@link Point} will have been doubled.
     */
    public abstract Point doubling();

    /**
     * Return a Point which is result of multiplying of Point.
     *
     * <p>
     * A multiplication on elliptic curve is defined as a lot of addition. However, just adding
     * spend a lot of time to calculate, so use 'double-and-add' algorithm or some others.
     * See also brief description of
     * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication">Elliptic curve point multiplication</a>
     *
     * <p>
     * If {@code integer} is equal to {@link BigInteger#ZERO}, this method must return the origin
     * point which is Point(0, 1).
     *
     * @param integer scalar value to multiply Point.
     * @return {@link Point} which will be multiplied.
     */
    public abstract Point scalarMultiply(BigInteger integer);

    /**
     * Return a negated Point.
     * <p>
     * Negation of coordinate y means you will get Point(x, -y mod P).
     * Prime P depends on each curves of elliptic curve.
     *
     * @return {@code Point(x, -y mod P)}.
     */
    public abstract Point negateY();

    /**
     * Encode this Point to an {@link EncodedPoint} object.
     *
     * <p>
     * Point can be encoded as follows.
     * <ul>
     * <li>First, encode the y-coordinate as a little-endian string. ths most significant bit
     * of the final octet is always zero.
     * <li>Second, copy the least significant bit of the x-coordinate to the most significant
     * bit of the final octet.
     * </ul>
     *
     * @return {@link EncodedPoint}
     */
    public abstract EncodedPoint encode();

    /**
     * Check value equality between two Points.
     * <p>Pay attention not to check different Point implementation. Below code will throw
     * {@link IllegalComparisonException}.
     * <pre>
     *      {@code
     *          Point point25519 = new PointEd25519(...);
     *          Point point448 = new PointEd448(...);
     *          point25519.isEqual(point448);
     *      }
     * </pre>
     *
     * @param point target {@link Point} to check value.
     * @return true, if both Points have {@link Coordinate}s which have the same value each.
     * false, others.
     * @throws IllegalComparisonException when you compare different Point implementations.
     */
    public boolean isEqual(Point point) {
        if (point.getClass() != this.getClass()) {
            String thisPointData = getClass().getSimpleName() + "{" +
                    x.value.toString() + ", " +
                    y.value.toString() + ", " +
                    z.value.toString() + "}";
            String pointData = point.getClass().getSimpleName() + "{" +
                    point.getX().value.toString() + ", " +
                    point.getY().value.toString() + ", " +
                    point.getZ().value.toString() + "}";
            throw new IllegalComparisonException("These points (" +
                    thisPointData + ", " +
                    pointData + ") can not be compared. Different point implementation.");
        }

        return point.getX().isEqual(this.x) && point.getY().isEqual(this.y) && point.getZ().isEqual(this.z);
    }
}
