package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;

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
        Coordinate x = new Coordinate(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"));
        Coordinate y = new Coordinate(new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"));
        return new Point(x, y);
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
