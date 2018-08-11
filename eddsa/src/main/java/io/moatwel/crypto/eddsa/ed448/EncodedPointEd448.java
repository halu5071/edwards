package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;

/**
 * Encoded Point implementation of ed448 curve. Implements {@link EncodedPoint#decode()}
 * operation. This object has byte array whose length is 57, which represents encoded point.
 */
class EncodedPointEd448 extends EncodedPoint {

    EncodedPointEd448(byte[] value) {
        if (value.length != 57) {
            throw new IllegalArgumentException("EncodedPoint on ed448 curve must have 57 byte length.");
        }
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point decode() {
        // TODO: will implement
        return null;
    }
}
