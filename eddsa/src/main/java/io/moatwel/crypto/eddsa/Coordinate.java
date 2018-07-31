package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 */
public abstract class Coordinate implements Cloneable {

    protected BigInteger value;

    public BigInteger getInteger() {
        return this.value;
    }

    /**
     *
     * @param coordinate
     * @return
     */
    public abstract Coordinate add(Coordinate coordinate);

    /**
     *
     * @param coordinate
     * @return
     */
    public abstract Coordinate divide(Coordinate coordinate);

    /**
     *
     * @param coordinate
     * @return
     */
    public abstract Coordinate multiply(Coordinate coordinate);

    /**
     *
     * @param coordinate
     * @return
     */
    public abstract Coordinate subtract(Coordinate coordinate);

    /**
     *
     * @return
     */
    public abstract Coordinate mod();

    /**
     *
     * @return
     */
    public abstract Coordinate inverse();

    /**
     *
     * @param integer
     * @return
     */
    public abstract Coordinate powerMod(BigInteger integer);

    /**
     * Check value equality between two Coordinates.
     * <p>Pay attention not to check different Coordinate implementation. Below code will throw
     * RuntimeException.
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
            throw new RuntimeException("These coordinates can not be compared. Different coordinate implementations");
        }
        return value.compareTo(coordinate.getInteger()) == 0;
    }

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
