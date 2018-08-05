package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import javax.annotation.Nonnull;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

public class PointEd25519 extends Point {

    private static final Point ZERO =
            new PointEd25519(new CoordinateEd25519(BigInteger.ZERO), new CoordinateEd25519(BigInteger.ONE));

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public PointEd25519(@Nonnull Coordinate x, @Nonnull Coordinate y) {
        super(x, y);
        curve = Ed25519Curve.getCurve();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final Point add(Point point) {
        // z = 1
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate x2 = point.getX();
        Coordinate y2 = point.getY();

        Coordinate t1 = x1.multiply(y1);
        Coordinate t2 = x2.multiply(y2);

        Coordinate d = new CoordinateEd25519(curve.getD().getInteger());
        Coordinate coord2 = new CoordinateEd25519(BigInteger.ONE.shiftLeft(1));

        Coordinate A = y1.subtract(x1).multiply(y2.subtract(x2)).mod();
        Coordinate B = y1.add(x1).multiply(y2.add(x2)).mod();
        Coordinate C = t1.multiply(d).multiply(t2).multiply(coord2).mod();
        Coordinate D = coord2;
        Coordinate E = B.subtract(A);
        Coordinate F = D.subtract(C);
        Coordinate G = D.add(C);
        Coordinate H = B.add(A);

        Coordinate Z3 = F.multiply(G);

        Coordinate x3 = E.multiply(F).multiply(Z3.inverse()).mod();
        Coordinate y3 = G.multiply(H).multiply(Z3.inverse()).mod();

        return new PointEd25519(x3, y3);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final Point scalarMultiply(BigInteger integer) {
        if (integer.equals(BigInteger.ZERO)) {
            return new PointEd25519(new CoordinateEd25519(BigInteger.ZERO), new CoordinateEd25519(BigInteger.ONE));
        }

        Point[] points = new Point[2];
        points[0] = this;
        int[] bin = ByteUtils.toBinaryArray(integer);

        for (int i = 1; i < bin.length; i++) {
            points[0] = points[0].add(points[0]);
            points[1] = points[0].add(this);
            points[0] = points[bin[i]];
        }
        return points[0];
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(y.getInteger(), 32));
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
}
