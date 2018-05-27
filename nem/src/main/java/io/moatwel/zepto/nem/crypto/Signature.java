package io.moatwel.zepto.nem.crypto;

import java.math.BigInteger;

import io.moatwel.zepto.nem.utils.ArrayUtils;

public class Signature {

    private static final BigInteger MAX_VALUE = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    private final byte[] r;
    private final byte[] s;

    public Signature(byte[] r, byte[] s) {
        if (r.length != 32 || s.length != 32) {
            throw new IllegalArgumentException("r and s must both have 32 bit length.");
        }
        this.r = r;
        this.s = s;
    }

    public Signature(BigInteger r, BigInteger s) {
        if (r.compareTo(MAX_VALUE) > 0 || s.compareTo(MAX_VALUE) > 0) {
            throw new IllegalArgumentException("r and s fit into 32 bytes");
        }
        this.r = r.toByteArray();
        this.s = s.toByteArray();
    }

    public Signature(byte[] bytes) {
        if (bytes.length != 64) {
            throw new IllegalArgumentException("binary signature representation must be 64 bytes");
        }
        final byte[][] part = ArrayUtils.split(bytes, 32);
        this.r = part[0];
        this.s = part[1];
    }

    public BigInteger getR() {
        return ArrayUtils.toBigInteger(r);
    }

    public BigInteger getS() {
        return ArrayUtils.toBigInteger(s);
    }

    public byte[] getBinaryR() {
        return this.r;
    }

    public byte[] getBinaryS() {
        return this.s;
    }
}
