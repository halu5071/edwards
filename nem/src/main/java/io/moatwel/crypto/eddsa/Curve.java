package io.moatwel.crypto.eddsa;

import java.math.BigInteger;

public interface Curve {

    int getPublicKeyByteLength();

    Point getBasePoint();

    BigInteger getPrimeL();

    BigInteger getPrimePowerP();

    Coordinate getD();

    BigInteger getHalfGroupOrder();
}
