package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;

public class Ed448Curve implements Curve {

    private static final Ed448Curve ED_448_CURVE;

    static {
        ED_448_CURVE = new Ed448Curve();
    }

    private Ed448Curve(){}

    @Override
    public int getPublicKeyByteLength() {
        return 57;
    }

    @Override
    public Point getBasePoint() {
        return null;
    }

    @Override
    public BigInteger getPrimeL() {
        return BigInteger.ONE.shiftLeft(448).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    }

    @Override
    public BigInteger getPrimePowerP() {
        return BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(new BigInteger("1"));
    }

    @Override
    public Coordinate getD() {
        BigInteger d = new BigInteger("-39081");
        //TODO Coordinate can not handle 52byte coordinate
        return new Coordinate(d);
    }

    @Override
    public BigInteger getHalfGroupOrder() {
        return null;
    }

    public static Ed448Curve getCurve() {
        return ED_448_CURVE;
    }
}
