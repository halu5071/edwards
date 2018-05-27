package io.moatwel.zepto.nem.crypto;

import java.math.BigInteger;

public interface Curve {

    String getName();

    BigInteger getGroupOrder();

    BigInteger getHalfGroupOrder();
}
