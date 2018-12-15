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
     * @throws DecodeException if a point you want to decode is not on your curve.
     */
    public abstract Point decode() throws DecodeException;
}
