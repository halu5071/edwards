package io.moatwel.crypto.eddsa.ed448;

import com.squareup.jnagmp.Gmp;

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
    public Coordinate add(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd448(value.add(integer));
    }

    @Override
    public Coordinate divide(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd448(Gmp.exactDivide(value, integer));
    }

    @Override
    public Coordinate multiply(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd448(value.multiply(integer));
    }

    @Override
    public Coordinate subtract(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd448(value.subtract(integer));
    }

    @Override
    public Coordinate mod() {
        return new CoordinateEd448(getInteger().mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate inverse() {
        return new CoordinateEd448(Gmp.modInverse(value, curve.getPrimePowerP()));
    }

    @Override
    public Coordinate powerMod(BigInteger exponent) {
        return new CoordinateEd448(Gmp.modPowSecure(value, exponent, curve.getPrimePowerP()));
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
