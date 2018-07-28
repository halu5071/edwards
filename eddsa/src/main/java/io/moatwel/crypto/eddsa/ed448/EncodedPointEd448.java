package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;

public class EncodedPointEd448 extends EncodedPoint {

    EncodedPointEd448(byte[] value) {
        if (value.length != 57) {
            throw new IllegalArgumentException("EncodedPoint on ed448 curve must have 57 byte length.");
        }
        this.value = value;
    }

    @Override
    public Point decode() {
        // TODO: will implement
        return null;
    }
}
