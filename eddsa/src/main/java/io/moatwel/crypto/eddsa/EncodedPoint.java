package io.moatwel.crypto.eddsa;

public abstract class EncodedPoint {

    protected byte[] value;

    public byte[] getValue() {
        return value;
    }

    public abstract Point decode();
}
