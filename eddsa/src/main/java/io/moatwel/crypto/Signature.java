package io.moatwel.crypto;

import java.math.BigInteger;

import io.moatwel.util.ByteUtils;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 */
public abstract class Signature {

    protected byte[] r;
    protected byte[] s;

    public byte[] getR() {
        return r;
    }

    public BigInteger getIntegerR() {
        return new BigInteger(1, r);
    }

    public byte[] getS() {
        return s;
    }

    public BigInteger getIntegerS() {
        return new BigInteger(1, s);
    }

    public byte[] getSignature() {
        return ByteUtils.join(r, s);
    }
}
