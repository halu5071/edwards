package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * Represent Point on Curve448 of Edwards-curve.
 *
 * @author Yasunori Horii.
 */
class PointEd448 extends Point {

    static final PointEd448 O = new PointEd448(CoordinateEd448.ZERO, CoordinateEd448.ONE);

    private static final Coordinate Z1 = new CoordinateEd448(BigInteger.ONE);
    private static final Coordinate Z2 = new CoordinateEd448(BigInteger.ONE);
    private static final Curve curve = Curve448.getInstance();

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    PointEd448(Coordinate x, Coordinate y) {
        super(x, y);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point add(Point point) {
        Coordinate x1 = this.x.multiply(Z1).mod();
        Coordinate y1 = this.y.multiply(Z1).mod();
        Coordinate x2 = point.getX().multiply(Z2).mod();
        Coordinate y2 = point.getY().multiply(Z2).mod();

        Coordinate A = Z1.multiply(Z2);
        Coordinate B = A.multiply(A);
        Coordinate C = x1.multiply(x2).mod();
        Coordinate D = y1.multiply(y2).mod();

        Coordinate E = curve.getD().multiply(C).multiply(D).mod();
        Coordinate F = B.subtract(E).mod();
        Coordinate G = B.add(E);
        Coordinate H = (x1.add(y1)).multiply(x2.add(y2)).mod();
        Coordinate X3 = A.multiply(F).multiply(H.subtract(C).subtract(D)).mod();
        Coordinate Y3 = A.multiply(G).multiply(D.subtract(C)).mod();
        Coordinate Z3 = F.multiply(G).mod();

        Coordinate x3 = X3.multiply(Z3.inverse()).mod();
        Coordinate y3 = Y3.multiply(Z3.inverse()).mod();

        return new PointEd448(x3, y3);
    }

    @Override
    public Point doubling() {
        // no-op temporally
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point scalarMultiply(BigInteger integer) {
        if (integer.equals(BigInteger.ZERO)) {
            return PointEd448.O;
        }

        Point[] qs = new Point[]{O, O};
        Point[] rs = new Point[]{this, this, negateY()};

        int[] signedBin = ArrayUtils.toMutualOppositeForm(integer);

        for (int aSignedBin : signedBin) {
            qs[0] = qs[0].add(qs[0]);
            qs[1] = ((PointEd448) qs[0].add(rs[1 - aSignedBin])).negate();
            qs[0] = qs[(aSignedBin ^ (aSignedBin >> 31)) - (aSignedBin >> 31)];
        }

        return qs[0];
    }

    @Override
    public Point negateY() {
        return new PointEd448(x, y.negate());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(y.getInteger(), 57));
        reversedY = ByteUtils.paddingZeroOnTail(reversedY, 57);
        byte[] byteX = ArrayUtils.toByteArray(x.getInteger(), 57);
        int lengthX = byteX.length;
        int lengthY = reversedY.length;
        int writeBit = byteX[lengthX - 1] & 0b00000001;

        if (writeBit == 1) {
            reversedY[lengthY - 1] |= 1 << 7;
        } else {
            writeBit = ~(1 << 7);
            reversedY[lengthY - 1] &= writeBit;
        }

        return new EncodedPointEd448(reversedY);
    }

    private Point negate() {
        return new PointEd448(x.negate(), y.negate());
    }
}
