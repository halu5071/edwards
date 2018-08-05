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
public class CoordinateEd448 extends Coordinate {

    private static final Curve curve = Ed448Curve.getCurve();

    public CoordinateEd448(BigInteger integer) {
        this.value = integer;
    }

    @Override
    public Coordinate add(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd448(integer1.add(integer2));
    }

    @Override
    public Coordinate divide(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd448(integer1.divide(integer2));
    }

    @Override
    public Coordinate multiply(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd448(integer1.multiply(integer2));
    }

    @Override
    public Coordinate subtract(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd448(integer1.subtract(integer2));
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
