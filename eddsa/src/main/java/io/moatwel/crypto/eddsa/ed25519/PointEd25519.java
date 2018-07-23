package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import javax.annotation.Nonnull;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;

public class PointEd25519 extends Point {

    static {
        ZERO = new PointEd25519(new CoordinateEd25519(BigInteger.ZERO), new CoordinateEd25519(BigInteger.ONE));
    }

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
        Coordinate a = new CoordinateEd25519(curve.getA());

        Coordinate x3 = x1.multiply(y2).mod().add(x2.multiply(y1))
                .multiply(CoordinateEd25519.ONE.add(d.multiply(x1.multiply(x2).mod().multiply(y1).multiply(y2)).mod()).inverse());

        Coordinate y3 = y1.multiply(y2).subtract(a.multiply(x1.multiply(x2).mod()))
                .multiply(CoordinateEd25519.ONE.subtract(d.multiply(x1.multiply(x2).mod().multiply(y1).mod().multiply(y2))).inverse());

        return new PointEd25519(x3.mod(), y3.mod());
    }

    @Override
    public Point scalarMultiply(BigInteger integer) {
        if (integer.equals(BigInteger.ZERO)) {
            return new PointEd25519(new CoordinateEd25519(BigInteger.ZERO), new CoordinateEd25519(BigInteger.ONE));
        }

        Point result = this.clone();
        int[] bin = ByteUtils.toBinaryArray(integer);

        for (int i = 1; i < bin.length; i++) {
            result = result.add(result);
            if (bin[i] == 1) {
                result = result.add(this);
            }
        }
        return result;
    }

    @Override
    public EncodedPoint encode() {
        byte[] reversedY = ByteUtils.reverse(y.getInteger().toByteArray());
        int lengthX = x.getInteger().toByteArray().length;
        int lengthY = reversedY.length;
        int writeBit = x.getInteger().toByteArray()[lengthX - 1] & 0b00000001;

        if (writeBit == 1) {
            reversedY[lengthY - 1] |= 1 << 7;
        } else {
            writeBit = ~(1 << 7);
            reversedY[lengthY - 1] &= writeBit;
        }

        return new EncodedPointEd25519(reversedY);
    }
}
