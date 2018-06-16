package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 * Represent Ed25519 curve of twisted Edwards-curve.
 *
 * @author halu5071 (Yasunori Horii)
 * @see <a href="https://tools.ietf.org/html/rfc8032#section-5.1">RFC 8032 Ed25519</a>
 */
public class Ed25519Curve implements Curve {

    private static final Ed25519Curve ED_CURVE;

    static {
        ED_CURVE = new Ed25519Curve();
    }

    private Ed25519Curve() {
    }

    @Override
    public int getPublicKeyByteLength() {
        return 32;
    }

    @Override
    public Point getBasePoint() {
        Coordinate x = new Coordinate(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
        Coordinate y = new Coordinate(new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
        return new Point(x, y);
    }

    @Override
    public BigInteger getPrimeL() {
        return BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    }

    @Override
    public BigInteger getPrimePowerP() {
        return BigInteger.ONE.shiftLeft(255).subtract(new BigInteger("19"));
    }

    @Override
    public Coordinate getD() {
        BigInteger d = new BigInteger("-121665")
                .multiply(new BigInteger("121666").modInverse(getPrimePowerP()))
                .mod(getPrimePowerP());
        return new Coordinate(d);
    }

    @Override
    public PublicKeyDelegate getPublicKeyGeneratorDelegate() {
        return new Ed25519PublicKeyDelegate(this);
    }

    @Override
    public EdDsaSigner getSigner() {
        return new Ed25519Signer();
    }

    public static Ed25519Curve getCurve() {
        return ED_CURVE;
    }
}
