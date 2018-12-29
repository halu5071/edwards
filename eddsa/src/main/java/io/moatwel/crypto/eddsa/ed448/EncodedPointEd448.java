package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;

/**
 * Encoded Point implementation of ed448 curve. Implements {@link EncodedPoint#decode()}
 * operation. This object has byte array whose length is 57, which represents encoded point.
 */
class EncodedPointEd448 extends EncodedPoint {

    private static final Curve curve = Curve448.getInstance();

    EncodedPointEd448(byte[] value) {
        super(value);
        if (value.length != 57) {
            throw new IllegalArgumentException("EncodedPoint on ed448 curve must have 57 byte length. " +
                    "The length of your EncodedPoint was " + value.length);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point decode() throws DecodeException {
        byte readTarget = value[value.length - 1];
        int x0 = ByteUtils.readBit(readTarget, 7);

        this.value[value.length - 1] &= 0x7F;
        BigInteger ySeed = new BigInteger(1, ByteUtils.reverse(this.value));
        if (ySeed.compareTo(curve.getPrimePowerP()) >= 1) {
            throw new DecodeException("EdDsa decoding failed. This point is not on the Curve448.");
        }
        Coordinate y = new CoordinateEd448(ySeed);

        Coordinate u = y.multiply(y).subtract(CoordinateEd448.ONE).mod();
        Coordinate v = curve.getD().multiply(y).multiply(y).subtract(CoordinateEd448.ONE).mod();
        Coordinate xx = u.multiply(v.inverse()).mod();

        Coordinate x = xx.powerMod(curve.getPrimePowerP().add(BigInteger.ONE).divide(BigInteger.ONE.shiftLeft(2)));

        if (x.multiply(x).mod().subtract(xx).getInteger().compareTo(BigInteger.ZERO) != 0) {
            throw new DecodeException("EdDsa decoding failed. This encoded point is not on the Curve448");
        }

        if (x.isEqual(CoordinateEd448.ZERO) && x0 == 1) {
            throw new DecodeException("EdDsa decoding failed.");
        }

        if (x.getInteger().mod(BigInteger.ONE.shiftLeft(1)).compareTo(BigInteger.valueOf((long) x0)) != 0) {
            x = new CoordinateEd448(BigInteger.ZERO.subtract(x.getInteger()).mod(curve.getPrimePowerP()));
        }

        return new PointEd448(x, y);
    }
}
