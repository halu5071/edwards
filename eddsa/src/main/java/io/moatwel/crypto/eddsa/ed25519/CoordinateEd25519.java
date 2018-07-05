package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;
import java.util.BitSet;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.util.ByteUtils;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
public class CoordinateEd25519 extends Coordinate {

    private static final Curve curve = Ed25519Curve.getCurve();

    static {
        ZERO = new CoordinateEd25519(new BigInteger("0"));
        ONE = new CoordinateEd25519(new BigInteger("1"));
    }

    public CoordinateEd25519(BigInteger integer) {
        this.value = integer;
    }

    @Override
    public Coordinate add(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.add(integer2));
    }

    @Override
    public Coordinate divide(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.divide(integer2));
    }

    @Override
    public Coordinate multiply(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.multiply(integer2));
    }

    @Override
    public Coordinate subtract(Coordinate coordinate) {
        BigInteger integer1 = this.value;
        BigInteger integer2 = coordinate.getInteger();
        return new CoordinateEd25519(integer1.subtract(integer2));
    }

    @Override
    public Coordinate mod() {
        return new CoordinateEd25519(getInteger().mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate inverse() {
        BigInteger integer = this.getInteger();
        return new CoordinateEd25519(integer.modInverse(curve.getPrimePowerP()));
    }
}
