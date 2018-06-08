package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

/**
 * Represent curve of twisted Edwards-curve.
 *
 * Some curve has been recommended by RFC.
 *
 * @author halu5071 (Yasunori Horii)
 * @see <a href="https://tools.ietf.org/html/rfc8032">RFC 8032</a>.
 */
public interface Curve {

    int getPublicKeyByteLength();

    /**
     * Represent BasePoint of this curve. See RFC8032
     *
     * @return {@link Point} instance of BasePoint
     */
    Point getBasePoint();

    BigInteger getPrimeL();

    BigInteger getPrimePowerP();

    Coordinate getD();

    /**
     * provide PublicKeyGeneratorDelegate instance.
     *
     * @return {@link PublicKeyGeneratorDelegate} instance for each curve.
     */
    PublicKeyGeneratorDelegate getPublicKeyGeneratorDelegate();
}
