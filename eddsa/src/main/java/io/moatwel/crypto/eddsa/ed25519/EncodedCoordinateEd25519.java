package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

public class EncodedCoordinateEd25519 extends EncodedCoordinate {

    EncodedCoordinateEd25519(byte[] value) {
        this.value = value;
    }

    @Override
    public Coordinate decode() {
        byte[] seed = ByteUtils.reverse(this.value);
        return new CoordinateEd25519(new BigInteger(1, seed));
    }
}
