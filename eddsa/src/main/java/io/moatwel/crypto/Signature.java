package io.moatwel.crypto;

import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

/**
 * @author halu5071 (Yasunori Horii)
 */
public abstract class Signature {

    protected final byte[] r;
    protected final byte[] s;

    protected Signature(byte[] r, byte[] s) {
        this.r = r;
        this.s = s;
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

    public byte[] getSignature() {
        return ByteUtils.join(r, s);
    }

    public String asString() {
        return HexEncoder.getString(ByteUtils.join(r, s));
    }
}
