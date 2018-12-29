package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field.
 * <p>
 * A subclass of this must be immutable object. In other words, all operation
 * must create new object of result.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class Coordinate {

    protected final BigInteger value;

    protected Coordinate(BigInteger value) {
        this.value = value;
    }

    public BigInteger getInteger() {
        return this.value;
    }

    /**
     * Addition of Coordinate. Just Adding.
     *
     * @param coordinate target of addition.
     * @return added Coordinate.
     */
    public abstract Coordinate add(Coordinate coordinate);

    /**
     * Division of Coordinate. Just Division.
     *
     * @param coordinate target of division.
     * @return divided Coordinate.
     */
    public abstract Coordinate divide(Coordinate coordinate);

    /**
     * Multiplication of Coordinate. This method return value
     * which is applied mod operation.
     *
     * @param coordinate target of multiplication.
     * @return multiplied Coordinate.
     */
    public abstract Coordinate multiply(Coordinate coordinate);

    /**
     * Subtraction of Coordinate. Just subtraction.
     *
     * @param coordinate target of subtraction.
     * @return subtracted Coordinate.
     */
    public abstract Coordinate subtract(Coordinate coordinate);

    /**
     * Return Coordinate contains a number for mod some number.
     *
     * @return modded Coordinate.
     */
    public abstract Coordinate mod();

    /**
     * @return
     */
    public abstract Coordinate inverse();

    /**
     * @param integer
     * @return
     */
    public abstract Coordinate powerMod(BigInteger integer);

    /**
     * Negate Coordinate value.
     * <p>
     * Note that a negated coordinate on elliptic-curve will be a positive integer by mod operation.
     * For example, negated 15112221349535400772501151409588531511454012693041857206046113283949847762202
     * on Curve25519 will be 42783823269122696939284341094755422415180979639778424813682678720006717057747.
     * <p>
     * See our test on CoordinateEd25519Test class.
     *
     * @return a Coordinate contains a positive integer.
     */
    public abstract Coordinate negate();

    /**
     * Check value equality between two Coordinates.
     * <p>Pay attention not to check different Coordinate implementation. Below code will throw
     * {@link IllegalComparisonException}.
     * <pre>
     *      {@code
     *          Coordinate coordinate1 = new CoordinateEd25519(...);
     *          Coordinate coordinate2 = new CoordinateEd448(...);
     *          coordinate1.isEqual(coordinate2);
     *      }
     * </pre>
     *
     * @param coordinate target {@link Coordinate} to check value.
     * @return true, if both Coordinate have {@link Coordinate}s which have the same value each.
     * false, others.
     * @throws RuntimeException when you check different Coordinate implementations.
     */
    public boolean isEqual(Coordinate coordinate) {
        if (coordinate.getClass() != this.getClass()) {
            throw new IllegalComparisonException("These coordinates can not be compared. Different coordinate implementations");
        }
        return value.compareTo(coordinate.getInteger()) == 0;
    }

    /**
     * All values on Edwards-curve can be encoded style. The method is depends on
     * each schemes.
     *
     * @return Encoded Coordinate.
     */
    public abstract EncodedCoordinate encode();
}
