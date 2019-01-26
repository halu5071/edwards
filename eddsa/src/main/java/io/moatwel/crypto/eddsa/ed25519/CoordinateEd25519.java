package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * Coordinate on Curve25519
 *
 * @author halu5071 (Yasunori Horii)
 */
class CoordinateEd25519 extends Coordinate {

    private static final Curve curve = Curve25519.getInstance();

    public static final CoordinateEd25519 ZERO = new CoordinateEd25519(BigInteger.ZERO);
    public static final Coordinate ONE = new CoordinateEd25519(BigInteger.ONE);

    CoordinateEd25519(BigInteger integer) {
        super(integer);
    }

    @Override
    public final Coordinate add(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd25519(value.add(integer));
    }

    @Override
    public final Coordinate divide(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd25519(value.divide(integer));
    }

    @Override
    public final Coordinate multiply(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd25519(value.multiply(integer));
    }

    @Override
    public final Coordinate subtract(Coordinate val) {
        BigInteger integer = val.getInteger();
        return new CoordinateEd25519(value.subtract(integer));
    }

    @Override
    public final Coordinate mod() {
        return new CoordinateEd25519(getInteger().mod(curve.getPrimePowerP()));
    }

    @Override
    public final Coordinate inverse() {
        BigInteger integer = this.getInteger();
        return new CoordinateEd25519(integer.modInverse(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate powerMod(BigInteger exponent) {
        return new CoordinateEd25519(this.value.modPow(exponent, curve.getPrimePowerP()));
    }

    @Override
    public Coordinate negate() {
        return new CoordinateEd25519(value.negate()).mod();
    }

    @Override
    public EncodedCoordinate encode() {
        byte[] seed = ByteUtils.reverse(ArrayUtils.toByteArray(value, 32));
        return new EncodedCoordinateEd25519(seed);
    }
}
