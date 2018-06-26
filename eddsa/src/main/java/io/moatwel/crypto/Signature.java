package io.moatwel.crypto;

import java.math.BigInteger;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 */
public abstract class Signature {

    protected byte[] r;
    protected byte[] s;

    public BigInteger getR() {
        return new BigInteger(r);
    }

    public BigInteger getS() {
        return new BigInteger(s);
    }

    public byte[] getBinaryR() {
        return this.r;
    }

    public byte[] getBinaryS() {
        return this.s;
    }
}
