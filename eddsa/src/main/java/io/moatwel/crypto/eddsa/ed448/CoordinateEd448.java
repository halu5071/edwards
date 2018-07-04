package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
public class CoordinateEd448 extends Coordinate {

    private static final Curve curve = Ed448Curve.getCurve();

    static {
        ZERO = new CoordinateEd448(new byte[57]);
        ONE = new CoordinateEd448(new BigInteger("1"));
    }

    public CoordinateEd448(byte[] value) {
        if (value.length != 57) {
            throw new IllegalArgumentException("Coordinate byte must have 32 byte length");
        }

        this.value = value;
    }

    public CoordinateEd448(BigInteger integer) {
        this(integer.toByteArray());
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
}
