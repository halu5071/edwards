package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import javax.annotation.Nonnull;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Point;

public class PointEd25519 extends Point {

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

    @Override
    public Point add(Point point) {
        Coordinate x1 = this.x;
        Coordinate y1 = this.y;
        Coordinate x2 = point.getX();
        Coordinate y2 = point.getY();

        Coordinate d = new CoordinateEd25519(curve.getD().getInteger());
        Coordinate a = new CoordinateEd25519(new BigInteger("" + curve.getA()));

        Coordinate x3 = x1.multiply(y2).add(x2.multiply(y1))
                .multiply(CoordinateEd25519.ONE.add(d.multiply(x1.multiply(x2).multiply(y1).multiply(y2))).inverse());

        Coordinate y3 = y1.multiply(y2).subtract(a.multiply(x1.multiply(x2)))
                .multiply(CoordinateEd25519.ONE.subtract(d.multiply(x1.multiply(x2).multiply(y1).multiply(y2))).inverse());

        return new PointEd25519(x3.mod(), y3.mod());
    }

    @Override
    public Point scalarMultiply(BigInteger integer) {
        return null;
    }
}
