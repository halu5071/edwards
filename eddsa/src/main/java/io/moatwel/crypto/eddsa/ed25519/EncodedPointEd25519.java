package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;

public class EncodedPointEd25519 extends EncodedPoint {

    EncodedPointEd25519(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("EncodedPoint on ed25519 curve must have 32 byte length.");
        }
        this.value = value;
    }

    @Override
    public Point decode() {
        // TODO: will implement
        return null;
    }
}
