package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represent curve of twisted Edwards-curve.
 * <p>
 * This class provide ONLY values which is unique on each edwards Curves.
 *
 * @author halu5071 (Yasunori Horii)
 * @see <a href="https://tools.ietf.org/html/rfc8032">RFC 8032</a>
 */
public abstract class Curve {

    public abstract int getPublicKeyByteLength();

    /**
     * Represent BasePoint of this curve. See RFC8032
     *
     * @return {@link Point} instance of BasePoint
     */
    public abstract Point getBasePoint();

    public abstract BigInteger getPrimeL();

    public abstract BigInteger getPrimePowerP();

    public abstract Coordinate getD();

    public abstract BigInteger getA();
}
