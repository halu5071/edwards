package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.Coordinate;

import java.math.BigInteger;

public class CoordinateEd25519TestFactory {

    public static Coordinate getOriginCoordinate() {
        return new CoordinateEd25519(BigInteger.ZERO);
    }
}
