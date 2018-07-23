package io.moatwel.crypto;

import java.math.BigInteger;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 */
public abstract class Signature {

    protected BigInteger r;
    protected BigInteger s;

    public BigInteger getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }
}
