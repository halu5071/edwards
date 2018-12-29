package io.moatwel.crypto.eddsa;

/**
 * Encoded Point on elliptic curve.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class EncodedPoint {

    protected final byte[] value;

    protected EncodedPoint(byte[] value) {
        this.value = value;
    }

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
