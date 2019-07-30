package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * Point class on Curve25519.
 *
 * @author halu5071 (Yasunori Horii)
 */
class PointEd25519 extends Point {

    private static final Coordinate DEFAULT_Z = new CoordinateEd25519(BigInteger.ONE);
    private static final Coordinate ONE = new CoordinateEd25519(BigInteger.ONE);
    private static final Coordinate ZERO = new CoordinateEd25519(BigInteger.ZERO);
    static final PointEd25519 O = new PointEd25519(ZERO, ONE, DEFAULT_Z, ZERO);
    private static final Curve curve = Curve25519.getInstance();

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    PointEd25519(Coordinate x, Coordinate y, Coordinate z, Coordinate t) {
        super(x, y, z, t);
    }

    public static PointEd25519 fromAffine(Coordinate x, Coordinate y) {
        return new PointEd25519(
                x.multiply(DEFAULT_Z).mod(),
                y.multiply(DEFAULT_Z).mod(),
                DEFAULT_Z,
                x.multiply(y).multiply(DEFAULT_Z).mod());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final Point add(Point point) {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate z1 = this.z;
        Coordinate t1 = this.t;
        Coordinate x2 = point.getX();
        Coordinate y2 = point.getY();
        Coordinate z2 = point.getZ();
        Coordinate t2 = point.getT();

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
        Coordinate t3 = E.multiply(H).mod();
        Coordinate z3 = F.multiply(G).mod();

        return new PointEd25519(x3, y3, z3, t3);
    }

    @Override
    public Point doubling() {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate z1 = this.z;

        Coordinate A = x1.multiply(x1).mod();
        Coordinate B = y1.multiply(y1).mod();
        Coordinate C = new CoordinateEd25519(BigInteger.ONE.shiftLeft(1)).multiply(z1).multiply(z1).mod();
        Coordinate H = A.add(B).mod();
        Coordinate E = H.subtract(x1.add(y1).multiply(x1.add(y1)).mod()).mod();
        Coordinate G = A.subtract(B).mod();
        Coordinate F = C.add(G).mod();

        Coordinate X3 = E.multiply(F).mod();
        Coordinate Y3 = G.multiply(H).mod();
        Coordinate T3 = E.multiply(H).mod();
        Coordinate Z3 = F.multiply(G).mod();

        return new PointEd25519(X3, Y3, Z3, T3);
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
            qs[1] = qs[0].add(rs[1 - aSignedBin]).negate();
            qs[0] = qs[(aSignedBin ^ (aSignedBin >> 31)) - (aSignedBin >> 31)];
        }
        return qs[0];
    }

    @Override
    public Point negateY() {
        return new PointEd25519(x, y.negate(), z, t.negate());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(getAffineY().getInteger(), 32));
        reversedY = ByteUtils.paddingZeroOnTail(reversedY, 32);
        byte[] byteX = ArrayUtils.toByteArray(getAffineX().getInteger(), 32);
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

    @Override
    public Point negate() {
        return new PointEd25519(x.negate(), y.negate(), z, t);
    }
}
