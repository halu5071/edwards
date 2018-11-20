package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
class CoordinateEd448 extends Coordinate {

    private static final Curve curve = Curve448.getInstance();

    CoordinateEd448(BigInteger integer) {
        this.value = integer;
    }

    @Override
    public Coordinate add(Coordinate coordinate) {
        BigInteger coord1 = this.getInteger();
        BigInteger coord2 = coordinate.getInteger();
        return new CoordinateEd448(coord1.add(coord2));
    }

    @Override
    public Coordinate divide(Coordinate coordinate) {
        BigInteger coord1 = this.getInteger();
        BigInteger coord2 = coordinate.getInteger();
        return new CoordinateEd448(coord1.divide(coord2));
    }

    @Override
    public Coordinate multiply(Coordinate coordinate) {
        BigInteger coord1 = this.getInteger();
        BigInteger coord2 = coordinate.getInteger();
        return new CoordinateEd448(coord1.multiply(coord2));
    }

    @Override
    public Coordinate subtract(Coordinate coordinate) {
        BigInteger coord1 = this.getInteger();
        BigInteger coord2 = coordinate.getInteger();
        return new CoordinateEd448(coord1.subtract(coord2));
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
    public EncodedCoordinate encode() {
        byte[] seed = ByteUtils.reverse(ArrayUtils.toByteArray(value, 57));
        return new EncodedCoordinateEd448(seed);
    }
}
