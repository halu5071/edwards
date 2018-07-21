package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;

public class EncodedPointEd25519 extends EncodedPoint {

    EncodedPointEd25519(byte[] value) {
        this.value = value;
    }

    @Override
    public Point decode() {
        return null;
    }
}
