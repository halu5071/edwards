package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;

public class CoordinateEd25519TestFactory {

    public static Coordinate getOriginCoordinate() {
        return new CoordinateEd25519(BigInteger.ZERO);
    }
}
