package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
class CoordinateEd25519 extends Coordinate {

    private static final Curve curve = Curve25519.getInstance();

    public static final CoordinateEd25519 ZERO = new CoordinateEd25519(new BigInteger("0"));
    public static final Coordinate ONE = new CoordinateEd25519(new BigInteger("1"));

    CoordinateEd25519(BigInteger integer) {
        this.value = integer;
    }

    @Override
    public final Coordinate add(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.add(integer2));
    }

    @Override
    public final Coordinate divide(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.divide(integer2));
    }

    @Override
    public final Coordinate multiply(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.multiply(integer2));
    }

    @Override
    public final Coordinate subtract(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.subtract(integer2));
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
    public Coordinate powerMod(BigInteger integer) {
        return new CoordinateEd25519(this.value.modPow(integer, curve.getPrimePowerP()));
    }

    @Override
    public EncodedCoordinate encode() {
        byte[] seed = ByteUtils.reverse(ArrayUtils.toByteArray(value, 32));
        return new EncodedCoordinateEd25519(seed);
    }
}
