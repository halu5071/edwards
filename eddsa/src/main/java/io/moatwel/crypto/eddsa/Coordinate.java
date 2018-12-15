package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 *
 * @author Yasunori Horii.
 */
public abstract class Coordinate implements Cloneable {

    protected BigInteger value;

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

    @Override
    public Coordinate clone() {
        Coordinate coordinate = null;
        try {
            coordinate = ((Coordinate) super.clone());
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
        }

        if (coordinate != null) {
            coordinate.value = value;
        }
        return coordinate;
    }
}
