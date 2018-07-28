package io.moatwel.crypto.eddsa;

public abstract class EncodedPoint {

    protected byte[] value;

    public byte[] getValue() {
        return value;
    }

    /**
     * EncodedPoint can be decode to {@link Point}.
     *
     * @return {@link Point}
     */
    public abstract Point decode();
}
