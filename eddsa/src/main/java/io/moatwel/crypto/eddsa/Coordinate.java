package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field.
 *
 * <p>
 * A subclass of this must be immutable object. In other words, all operation
 * must create new object of the result.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class Coordinate {

    protected final BigInteger value;

    protected Coordinate(BigInteger value) {
        this.value = value;
    }

    /**
     * Return integer value which this class contains.
     *
     * @return integer value which this class contains.
     */
    public BigInteger getInteger() {
        return this.value;
    }

    /**
     * Return a Coordinate whose value is {@code this + val}.
     *
     * @param val target of addition.
     * @return an added Coordinate.
     */
    public abstract Coordinate add(Coordinate val);

    /**
     * Return a Coordinate whose value is {@code this - val}.
     *
     * @param val target of division.
     * @return a divided Coordinate.
     */
    public abstract Coordinate divide(Coordinate val);

    /**
     * Return a Coordinate whose value is {@code this * val}.
     *
     * <p>
     * Pay attention to apply mod operation to the result.
     *
     * @param val target of multiplication.
     * @return a multiplied Coordinate.
     */
    public abstract Coordinate multiply(Coordinate val);

    /**
     * Return a Coordinate whose value is {@code this - val}.
     *
     * @param val target of subtraction.
     * @return a subtracted Coordinate.
     */
    public abstract Coordinate subtract(Coordinate val);

    /**
     * Return a Coordinate whose value is {@code this mod prime L}. Prime L
     * depends on each curves of elliptic curve.
     *
     * @return a modded Coordinate.
     */
    public abstract Coordinate mod();

    /**
     * Return {@link Coordinate} whose value is {@code 1/this mod prime L}.
     *
     * <p>
     * Pay attention that the prime L depends on each curves of elliptic curve.
     *
     * @return {@code 1/this mod prime L}
     */
    public abstract Coordinate inverse();

    /**
     * Return Coordinate whose value is {@code pow(this, exponent) mod prime L}.
     *
     * Pay attention that the prime L depends on each curves of elliptic curve.
     *
     * @param exponent the exponent
     * @return {@code pow(this exponent mod prime L}
     */
    public abstract Coordinate powerMod(BigInteger exponent);

    /**
     * Negate Coordinate value.
     *
     * <p>
     * Note that a negated coordinate on elliptic-curve will be a positive integer by mod operation.
     * <p>
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
     *
     * <p>Pay attention not to compare different {@link Coordinate} implementations. Below code will
     * throw {@link IllegalComparisonException}.
     *
     * <pre>
     *      {@code
     *          Coordinate coordinate25519 = new CoordinateEd25519(...);
     *          Coordinate coordinate448 = new CoordinateEd448(...);
     *          coordinate25519.isEqual(coordinate448);
     *      }
     * </pre>
     *
     * @param coordinate target {@link Coordinate} to check value.
     * @return true, if both Coordinate have {@link Coordinate}s which have the same value each.
     * false, others.
     * @throws RuntimeException when you compare different {@link Coordinate} implementations.
     */
    public boolean isEqual(Coordinate coordinate) {
        if (coordinate.getClass() != this.getClass()) {
            String thisClassData = getClass().getSimpleName() + ":" + value.toString();
            String coordClassData = coordinate.getClass().getSimpleName() + ":" + coordinate.value.toString();
            throw new IllegalComparisonException("These coordinates (" +
                    thisClassData + ", " +
                    coordClassData + ") can not be compared. Different coordinate implementations");
        }
        return value.compareTo(coordinate.getInteger()) == 0;
    }

    /**
     * Encode this Coordinate to an {@link EncodedCoordinate} object.
     *
     * <p>
     * All values on Edwards-curve can be encoded style. The method is depends on
     * each schemes.
     *
     * @return Encoded Coordinate.
     */
    public abstract EncodedCoordinate encode();
}
