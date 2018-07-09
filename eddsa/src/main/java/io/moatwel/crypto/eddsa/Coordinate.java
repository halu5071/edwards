package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 */
public abstract class Coordinate implements Cloneable {

    public static Coordinate ZERO;
    public static Coordinate ONE;

    protected BigInteger value;

    public BigInteger getInteger() {
        return this.value;
    }

    public abstract Coordinate add(Coordinate coordinate);

    public abstract Coordinate divide(Coordinate coordinate);

    public abstract Coordinate multiply(Coordinate coordinate);

    public abstract Coordinate subtract(Coordinate coordinate);

    public abstract Coordinate mod();

    public abstract Coordinate inverse();

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
