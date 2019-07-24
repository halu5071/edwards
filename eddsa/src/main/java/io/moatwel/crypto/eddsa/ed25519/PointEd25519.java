package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * Point class on Curve25519.
 *
 * @author halu5071 (Yasunori Horii)
 */
class PointEd25519 extends Point {

//    static final PointEd25519 O = PointEd25519.fromAffine(CoordinateEd25519.ZERO, CoordinateEd25519.ONE);
    static final PointEd25519 O = new PointEd25519(CoordinateEd25519.ZERO, CoordinateEd25519.ONE, CoordinateEd25519.ONE);

    private static final Coordinate DEFAULT_Z = new CoordinateEd25519(BigInteger.ONE);
    private static final Curve curve = Curve25519.getInstance();

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    PointEd25519(Coordinate x, Coordinate y, Coordinate z) {
        super(x, y, z);
    }

    public static PointEd25519 fromAffine(Coordinate x, Coordinate y) {
        return new PointEd25519(
                x.multiply(DEFAULT_Z).multiply(DEFAULT_Z).mod(),
                y.multiply(DEFAULT_Z).multiply(DEFAULT_Z).multiply(DEFAULT_Z).mod(),
                DEFAULT_Z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final Point add(Point point) {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate z1 = this.z;
        Coordinate x2 = point.getX();
        Coordinate y2 = point.getY();
        Coordinate z2 = point.getZ();

        Coordinate t1 = x1.multiply(y1).multiply(z1).mod();
        Coordinate t2 = x2.multiply(y2).multiply(z2).mod();

        Coordinate d = new CoordinateEd25519(curve.getD().getInteger());
        Coordinate coord2 = new CoordinateEd25519(BigInteger.ONE.shiftLeft(1));

        Coordinate A = y1.subtract(x1).multiply(y2.subtract(x2)).mod();
        Coordinate B = y1.add(x1).multiply(y2.add(x2)).mod();
        Coordinate C = t1.multiply(coord2).multiply(d).multiply(t2).mod();
        Coordinate D = z1.multiply(coord2).multiply(z2).mod();
        Coordinate E = B.subtract(A).mod();
        Coordinate F = D.subtract(C).mod();
        Coordinate G = D.add(C).mod();
        Coordinate H = B.add(A).mod();

        Coordinate x3 = E.multiply(F).mod();
        Coordinate y3 = G.multiply(H).mod();
        Coordinate z3 = F.multiply(G).mod();

        return new PointEd25519(x3, y3, z3);
    }

    @Override
    public Point doubling() {
        Coordinate x1 = this.x.multiply(DEFAULT_Z).mod();
        Coordinate y1 = this.y.multiply(DEFAULT_Z).mod();
        Coordinate A = x.multiply(x1).mod();
        Coordinate B = y.multiply(y1).mod();
        Coordinate C = new CoordinateEd25519(BigInteger.ONE.shiftLeft(1)).multiply(DEFAULT_Z).multiply(DEFAULT_Z).mod();
        Coordinate H = A.add(B).mod();
        Coordinate E = H.subtract(x1.add(y1).multiply(x1.add(y1))).mod();
        Coordinate G = A.subtract(B).mod();
        Coordinate F = C.add(G).mod();
        Coordinate X3 = E.multiply(F).mod();
        Coordinate Y3 = G.multiply(H).mod();
        Coordinate Z3 = F.multiply(G).mod().inverse();

        Coordinate x3 = X3.multiply(Z3).mod();
        Coordinate y3 = Y3.multiply(Z3).mod();

        return PointEd25519.fromAffine(x3, y3);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final Point scalarMultiply(BigInteger integer) {
        if (integer.equals(BigInteger.ZERO)) {
            return PointEd25519.O;
        }

        Point[] qs = new Point[]{O, O};
        Point[] rs = new Point[]{this, this, negateY()};

        int[] signedBin = ArrayUtils.toMutualOppositeForm(integer);

        for (int aSignedBin : signedBin) {
            qs[0] = qs[0].doubling();
            qs[1] = ((PointEd25519) qs[0].add(rs[1 - aSignedBin])).negate();
            qs[0] = qs[(aSignedBin ^ (aSignedBin >> 31)) - (aSignedBin >> 31)];
        }
        return qs[0];
    }

    @Override
    public Point negateY() {
        return PointEd25519.fromAffine(x, y.negate());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(y.getInteger(), 32));
        reversedY = ByteUtils.paddingZeroOnTail(reversedY, 32);
        byte[] byteX = ArrayUtils.toByteArray(x.getInteger(), 32);
        int lengthX = byteX.length;
        int lengthY = reversedY.length;
        int writeBit = byteX[lengthX - 1] & 0b00000001;

        if (writeBit == 1) {
            reversedY[lengthY - 1] |= 1 << 7;
        } else {
            writeBit = ~(1 << 7);
            reversedY[lengthY - 1] &= writeBit;
        }

        return new EncodedPointEd25519(reversedY);
    }

    private Point negate() {
        return PointEd25519.fromAffine(x.negate(), y.negate());
    }
}
