package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 */
public abstract class Coordinate {

    protected byte[] value;
    public static Coordinate ZERO;
    public static Coordinate ONE;

    public byte[] getValue() {
        return this.value;
    }

    public BigInteger getInteger() {
        return new BigInteger(this.value);
    }

    public abstract Coordinate add(Coordinate coordinate);

    public abstract Coordinate divide(Coordinate coordinate);

    public abstract Coordinate multiply(Coordinate coordinate);

    public abstract Coordinate subtract(Coordinate coordinate);

    public abstract Coordinate mod();

    public abstract Coordinate inverse();
}
