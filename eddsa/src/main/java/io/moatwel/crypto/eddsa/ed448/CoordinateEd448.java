package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * Coordinate on Curve448.
 *
 * @author halu5071 (Yasunori Horii)
 */
class CoordinateEd448 extends Coordinate {

    public static final Coordinate ZERO = new CoordinateEd448(BigInteger.ZERO);
    public static final Coordinate ONE = new CoordinateEd448(BigInteger.ONE);

    private static final Curve curve = Curve448.getInstance();

    CoordinateEd448(BigInteger integer) {
        super(integer);
    }

    @Override
    public Coordinate add(Coordinate coordinate) {
        BigInteger integer = coordinate.getInteger();
        return new CoordinateEd448(value.add(integer));
    }

    @Override
    public Coordinate divide(Coordinate coordinate) {
        BigInteger integer = coordinate.getInteger();
        return new CoordinateEd448(value.divide(integer));
    }

    @Override
    public Coordinate multiply(Coordinate coordinate) {
        BigInteger integer = coordinate.getInteger();
        return new CoordinateEd448(value.multiply(integer));
    }

    @Override
    public Coordinate subtract(Coordinate coordinate) {
        BigInteger integer = coordinate.getInteger();
        return new CoordinateEd448(value.subtract(integer));
    }

    @Override
    public Coordinate mod() {
        return new CoordinateEd448(getInteger().mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate inverse() {
        BigInteger integer = this.getInteger();
        return new CoordinateEd448(integer.modInverse(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate powerMod(BigInteger integer) {
        return new CoordinateEd448(this.value.modPow(integer, curve.getPrimePowerP()));
    }

    @Override
    public Coordinate negate() {
        return new CoordinateEd448(value.negate()).mod();
    }

    @Override
    public EncodedCoordinate encode() {
        byte[] seed = ByteUtils.reverse(ArrayUtils.toByteArray(value, 57));
        return new EncodedCoordinateEd448(seed);
    }
}
