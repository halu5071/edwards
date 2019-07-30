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

    private static final BigInteger P = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(new BigInteger("1"));
    private static final BigInteger L = BigInteger.ONE.shiftLeft(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    private static final Coordinate D = new CoordinateEd448(new BigInteger("-39081"));

    // arg t is unnecessary on scalar multiplication indeed, so set ONE as arg t.
    private static final Point BASE = new PointEd448(
            new CoordinateEd448(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710")),
            new CoordinateEd448(new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660")),
            CoordinateEd448.ONE,
            CoordinateEd448.ONE
    );

    private Curve448() {
    }

    public static Curve448 getInstance() {
        return CurveHolder.INSTANCE;
    }

    @Override
    public int getPublicKeyByteLength() {
        return 57;
    }

    @Override
    public Point getBasePoint() {
        return BASE;
    }

    @Override
    public BigInteger getPrimeL() {
        return L;
    }

    @Override
    public BigInteger getPrimePowerP() {
        return P;
    }

    @Override
    public Coordinate getD() {
        return D;
    }

    @Override
    public BigInteger getA() {
        return BigInteger.ONE;
    }

    private static class CurveHolder {
        private static final Curve448 INSTANCE = new Curve448();
    }
}
