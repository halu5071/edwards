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
        ZERO = new CoordinateEd25519(new byte[32]);
        ONE = new CoordinateEd25519(new BigInteger("1"));
    }

    public CoordinateEd25519(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("CoordinateEd25519 must have 32 byte length");
        }

        this.value = value;
    }

    public CoordinateEd25519(BigInteger integer) {
        byte[] input = integer.toByteArray();
        if (input.length > 32) {
            throw new IllegalArgumentException("CoordinateEd25519 must have byte array whose length less than 32");
        }
        this.value = ByteUtils.paddingZero(input, 32);
    }

    @Override
    public Coordinate add(Coordinate coordinate) {
        BigInteger integer1 = new BigInteger(this.value);
        BigInteger integer2 = new BigInteger(coordinate.getValue());
        return new CoordinateEd25519(integer1.add(integer2).mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate divide(Coordinate coordinate) {
        BigInteger integer1 = new BigInteger(this.value);
        BigInteger integer2 = new BigInteger(coordinate.getValue());
        return new CoordinateEd25519(integer1.divide(integer2).mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate multiply(Coordinate coordinate) {
        BigInteger integer1 = new BigInteger(this.value);
        BigInteger integer2 = new BigInteger(coordinate.getValue());
        return new CoordinateEd25519(integer1.multiply(integer2).mod(curve.getPrimePowerP()));
    }

    @Override
    public Coordinate subtract(Coordinate coordinate) {
        BigInteger integer1 = new BigInteger(this.value);
        BigInteger integer2 = new BigInteger(coordinate.getValue());
        return new CoordinateEd25519(integer1.subtract(integer2).mod(curve.getPrimePowerP()));
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
