package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

/**
 * Represents a element of the finite field with p=2^255-19
 *
 * value[0] - value[9], represent the integer
 * value[0] + 2^26 * value[1] + 2^51 * value[2] + 2^77 * value[3] + ... + 2^230 * value[9]
 * Bounds on each values[i] vary depending on context
 */
public class Coordinate {

    public static final Coordinate ZERO = null;
    public static final Coordinate ONE = null;
    public static final Coordinate TWO = null;

    public static final Coordinate D = Ed25519Curve.getEdCurve().getD();

    public static final byte[] ZERO_SHORT = new byte[32];
    public static final byte[] ZERO_LONG = new byte[64];

    private final byte[] value;

    public Coordinate(BigInteger integer) {
        this(integer.toByteArray());
    }

    public Coordinate(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("Invalid 2^256 bit representation");
        }
        this.value = value;
    }

    public byte[] getValue() {
        return this.value;
    }
}
