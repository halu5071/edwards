package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;

import java.math.BigInteger;

/**
 * Represent Ed25519 curve of twisted Edwards-curve.
 *
 * @author halu5071 (Yasunori Horii)
 * @see <a href="https://tools.ietf.org/html/rfc8032#section-5.1">RFC 8032 Ed25519</a>
 */
public class Curve25519 extends Curve {

    private static Curve25519 curve;

    private Curve25519() {
    }

    @Override
    public final int getPublicKeyByteLength() {
        return 32;
    }

    @Override
    public final Point getBasePoint() {
        Coordinate x = new CoordinateEd25519(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
        Coordinate y = new CoordinateEd25519(new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
        return new PointEd25519(x, y);
    }

    @Override
    public final BigInteger getPrimeL() {
        return BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    }

    @Override
    public final BigInteger getPrimePowerP() {
        return BigInteger.ONE.shiftLeft(255).subtract(new BigInteger("19"));
    }

    @Override
    public final Coordinate getD() {
        BigInteger d = new BigInteger("-121665")
                .multiply(new BigInteger("121666").modInverse(getPrimePowerP()))
                .mod(getPrimePowerP());
        return new CoordinateEd25519(d);
    }

    @Override
    public final BigInteger getA() {
        return new BigInteger("-1");
    }

    public static Curve25519 getInstance() {
        return CurveHolder.INSTANCE;
    }

    private static class CurveHolder {
        private static final Curve25519 INSTANCE = new Curve25519();
    }
}
