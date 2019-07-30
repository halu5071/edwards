package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * Encoded Point implementation of the Curve25519. Implements {@link EncodedPoint#decode()}
 * operation. This object has byte array whose length is 32, which represents encoded point.
 */
class EncodedPointEd25519 extends EncodedPoint {

    private static final Curve curve = Curve25519.getInstance();

    EncodedPointEd25519(byte[] value) {
        super(value);
        if (value.length != 32)
            throw new IllegalArgumentException("EncodedPoint on ed25519 curve must have " +
                    "32 byte length. The length of your EncodedPoint was " + value.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point decode() throws DecodeException {
        // read bit for recovering x
        byte readTarget = value[value.length - 1];
        int x0 = ByteUtils.readBit(readTarget, 7);

        Coordinate y = recoverY(this.value);

        Coordinate x = recoverX(y, x0);

        return PointEd25519.fromAffine(x, y);
    }

    private Coordinate recoverY(byte[] source) throws DecodeException {
        source[source.length - 1] &= 0x7F;
        BigInteger ySeed = new BigInteger(ByteUtils.reverse(source));
        if (ySeed.compareTo(curve.getPrimePowerP()) >= 1) {
            throw new DecodeException("EdDsa decoding failed. This point is not on the edwards Curve25519.");
        }
        return new CoordinateEd25519(ySeed);
    }

    private Coordinate recoverX(Coordinate y, int xSource) throws DecodeException {
        Coordinate one = new CoordinateEd25519(BigInteger.ONE);
        Coordinate u = y.multiply(y).subtract(one).mod();
        Coordinate v = (curve.getD().multiply(y).multiply(y).add(one)).mod();
        Coordinate xx = u.multiply(v.inverse()).mod();

        Coordinate x = xx.powerMod(curve.getPrimePowerP().add(new BigInteger("3")).divide(new BigInteger("8")));

        if (x.multiply(x).subtract(xx).mod().getInteger().compareTo(BigInteger.ZERO) != 0) {
            if (x.multiply(x).add(xx).mod().getInteger().compareTo(BigInteger.ZERO) == 0) {
                x = x.multiply(new CoordinateEd25519(
                        BigInteger.ONE.shiftLeft(1).modPow(
                                curve.getPrimePowerP().subtract(BigInteger.ONE).divide(BigInteger.ONE.shiftLeft(2)),
                                curve.getPrimePowerP()))).mod();
            } else {
                throw new DecodeException("EdDsa decoding failed.");
            }
        }

        BigInteger result = x.getInteger().mod(BigInteger.ONE.shiftLeft(1));
        if (result.compareTo(BigInteger.valueOf((long) xSource)) != 0) {
            x = new CoordinateEd25519(curve.getPrimePowerP().subtract(x.getInteger()).mod(curve.getPrimePowerP()));
        }

        return x;
    }
}
