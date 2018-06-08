package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 */
public class Coordinate {

    public static final Coordinate ZERO = new Coordinate(new byte[32]);
    public static final Coordinate ONE = null;
    public static final Coordinate TWO = null;

    private final byte[] values;

    public Coordinate(BigInteger integer) {
        this(integer.toByteArray());
    }

    public Coordinate(byte[] value) {
        if (value.length == 32) {
            this.values = value;
        } else {
            throw new IllegalArgumentException("Invalid  representation");
        }
    }

    public byte[] getValue() {
        return this.values;
    }

    public BigInteger getInteger() {
        return new BigInteger(this.values);
    }
}
