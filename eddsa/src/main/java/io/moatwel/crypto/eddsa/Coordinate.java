package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represents a element of the finite field
 */
public abstract class Coordinate {

    protected byte[] value;

    public byte[] getValue() {
        return this.value;
    }

    public BigInteger getInteger() {
        return new BigInteger(this.value);
    }
}
