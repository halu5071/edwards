package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

/**
 * Represents a element of the finite field
 */
public class Coordinate {

    public static final Coordinate ZERO = null;
    public static final Coordinate ONE = null;
    public static final Coordinate TWO = null;

    public static final Coordinate D = Ed25519Curve.getEdCurve().getD();

    public static final byte[] ZERO_SHORT = new byte[32];
    public static final byte[] ZERO_LONG = new byte[64];

    private final byte[] values;

    public Coordinate(BigInteger integer) {
        this(integer.toByteArray());
    }

    public Coordinate(byte[] value) {
        if (value.length == 32 || value.length == 56) {
            this.values = value;
        } else {
            throw new IllegalArgumentException("Invalid 2^256 or 2^456 bit representation");
        }
    }

    public byte[] getValue() {
        return this.values;
    }
}
