package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.ByteUtils;

class EncodedCoordinateEd448 extends EncodedCoordinate {

    EncodedCoordinateEd448(byte[] value) {
        super(value);
    }

    @Override
    public Coordinate decode() {
        byte[] seed = ByteUtils.reverse(this.value);
        return new CoordinateEd448(new BigInteger(1, seed));
    }
}
