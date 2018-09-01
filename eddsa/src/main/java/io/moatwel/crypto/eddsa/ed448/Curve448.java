package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;

import java.math.BigInteger;

/**
 * Represent Ed448 curve of twisted Edwards-curve.
 *
 * @author halu5071 (Yasunori Horii)
 * @see <a href="https://tools.ietf.org/html/rfc8032#section-5.2">RFC 8032 Ed448</a>
 */
public class Curve448 extends Curve {

    private static final Curve448 ED_448_CURVE;

    static {
        ED_448_CURVE = new Curve448();
    }

    private Curve448() {
    }

    @Override
    public int getPublicKeyByteLength() {
        return 57;
    }

    @Override
    public Point getBasePoint() {
        Coordinate x = new CoordinateEd448(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"));
        Coordinate y = new CoordinateEd448(new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"));
        return new PointEd448(x, y);
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
        return new CoordinateEd448(d);
    }

    @Override
    public BigInteger getA() {
        return BigInteger.ONE;
    }

    public static Curve448 getInstance() {
        return ED_448_CURVE;
    }
}
