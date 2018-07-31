package io.moatwel.crypto.eddsa;

public abstract class EncodedCoordinate {

    protected byte[] value;

    public byte[] getValue() {
        return value;
    }

    public abstract Coordinate decode();
}
