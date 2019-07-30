package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * Represent Point on Curve448 of Edwards-curve.
 *
 * @author Yasunori Horii.
 */
class PointEd448 extends Point {

    static final PointEd448 O = new PointEd448(CoordinateEd448.ZERO, CoordinateEd448.ONE, CoordinateEd448.ONE, CoordinateEd448.ZERO);
    private static final Coordinate DEFAULT_Z = CoordinateEd448.ONE;
    private static final Curve curve = Curve448.getInstance();

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    PointEd448(Coordinate x, Coordinate y, Coordinate z, Coordinate t) {
        super(x, y, z, t);
    }

    public static PointEd448 fromAffine(Coordinate x, Coordinate y) {
        return new PointEd448(
                x.multiply(DEFAULT_Z).mod(),
                y.multiply(DEFAULT_Z).mod(),
                DEFAULT_Z,
                x.multiply(y).multiply(DEFAULT_Z).mod()
        );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point add(Point point) {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate z1 = this.z;
        Coordinate x2 = point.getX();
        Coordinate y2 = point.getY();
        Coordinate z2 = point.getZ();

        Coordinate A = z1.multiply(z2).mod();
        Coordinate B = A.multiply(A).mod();
        Coordinate C = x1.multiply(x2).mod();
        Coordinate D = y1.multiply(y2).mod();

        Coordinate E = curve.getD().multiply(C).multiply(D).mod();
        Coordinate F = B.subtract(E).mod();
        Coordinate G = B.add(E);
        Coordinate H = (x1.add(y1)).multiply(x2.add(y2)).mod();
        Coordinate X3 = A.multiply(F).multiply(H.subtract(C).subtract(D)).mod();
        Coordinate Y3 = A.multiply(G).multiply(D.subtract(C)).mod();
        Coordinate Z3 = F.multiply(G).mod();

        // arg t is unnecessary on scalar multiplication indeed, so set ZERO as arg t.
        return new PointEd448(X3, Y3, Z3, CoordinateEd448.ZERO);
    }

    @Override
    public Point doubling() {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate z1 = this.z;

        Coordinate B = (x1.add(y1)).multiply(x1.add(y1)).mod();
        Coordinate C = x1.multiply(x1).mod();
        Coordinate D = y1.multiply(y1).mod();
        Coordinate E = C.add(D).mod();
        Coordinate H = z1.multiply(z1).mod();
        Coordinate J = E.subtract(new CoordinateEd448(BigInteger.ONE.shiftLeft(1)).multiply(H)).mod();

        Coordinate X3 = (B.subtract(E)).multiply(J).mod();
        Coordinate Y3 = E.multiply(C.subtract(D)).mod();
        Coordinate Z3 = E.multiply(J);

        // arg t is unnecessary on scalar multiplication indeed, so set ZERO as arg t.
        return new PointEd448(X3, Y3, Z3, CoordinateEd448.ZERO);
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
            qs[0] = qs[0].doubling();
            qs[1] = qs[0].add(rs[1 - aSignedBin]).negate();
            qs[0] = qs[(aSignedBin ^ (aSignedBin >> 31)) - (aSignedBin >> 31)];
        }
        return qs[0];
    }

    @Override
    public Point negateY() {
        return new PointEd448(x, y.negate(), z, t.negate());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(getAffineY().getInteger(), 57));
        reversedY = ByteUtils.paddingZeroOnTail(reversedY, 57);
        byte[] byteX = ArrayUtils.toByteArray(getAffineX().getInteger(), 57);
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

    @Override
    public Point negate() {
        return new PointEd448(x.negate(), y.negate(), z, t);
    }
}
