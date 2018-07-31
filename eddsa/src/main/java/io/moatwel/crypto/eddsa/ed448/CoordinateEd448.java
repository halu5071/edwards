package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.crypto.eddsa.EncodedPoint;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
public class CoordinateEd448 extends Coordinate {

    private static final Curve curve = Ed448Curve.getCurve();

    private static final Coordinate ZERO = new CoordinateEd448(new BigInteger("0"));
    private static final Coordinate ONE = new CoordinateEd448(new BigInteger("1"));

    public CoordinateEd448(BigInteger integer) {
        this.value = integer;
    }

    @Override
    public Coordinate add(Coordinate coordinate) {
        return null;
    }

    @Override
    public Coordinate divide(Coordinate coordinate) {
        return null;
    }

    @Override
    public Coordinate multiply(Coordinate coordinate) {
        return null;
    }

    @Override
    public Coordinate subtract(Coordinate coordinate) {
        return null;
    }

    @Override
    public Coordinate mod() {
        return new CoordinateEd448(getInteger().mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate inverse() {
        return null;
    }

    @Override
    public Coordinate powerMod(BigInteger integer) {
        return null;
    }

    @Override
    public EncodedCoordinate encode() {
        return null;
    }
}
