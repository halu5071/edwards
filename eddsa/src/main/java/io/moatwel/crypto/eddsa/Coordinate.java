package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 */
public abstract class Coordinate {

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
}
