package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;

class PointEd448 extends Point {

    private static final Coordinate Z1 = new CoordinateEd448(new BigInteger("1"));
    private static final Coordinate Z2 = new CoordinateEd448(new BigInteger("1"));

    /**
     * constructor of Point
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    PointEd448(Coordinate x, Coordinate y) {
        super(x, y);
        curve = Curve448.getInstance();

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
        Coordinate C = x1.multiply(x2);
        Coordinate D = y1.multiply(y2);

        Coordinate E = curve.getD().multiply(C).multiply(D);
        Coordinate F = B.subtract(E);
        Coordinate G = B.add(E);
        Coordinate H = (x1.add(y1)).multiply(x2.add(y2));
        Coordinate X3 = A.multiply(F).multiply(H.subtract(C).subtract(D));
        Coordinate Y3 = A.multiply(G).multiply(D.subtract(C));
        Coordinate Z3 = F.multiply(G);

        Coordinate x3 = X3.multiply(Z3.inverse()).mod();
        Coordinate y3 = Y3.multiply(Z3.inverse()).mod();

        return new PointEd448(x3, y3);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Point scalarMultiply(BigInteger integer) {
        if (integer.equals(BigInteger.ZERO)) {
            return new PointEd448(new CoordinateEd448(BigInteger.ZERO), new CoordinateEd448(BigInteger.ONE));
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
    public EncodedPoint encode() {
        return null;
    }
}
