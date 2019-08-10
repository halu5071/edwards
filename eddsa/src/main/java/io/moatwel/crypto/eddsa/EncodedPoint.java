package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.eddsa.ed25519.EncodedPointEd25519;
import io.moatwel.crypto.eddsa.ed448.EncodedPointEd448;

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

    public static EncodedPoint from(byte[] value) {
        switch (value.length) {
            case 32:
                return new EncodedPointEd25519(value);
            case 57:
                return new EncodedPointEd448(value);
            default:
                throw new IllegalArgumentException("Length(" + value.length + ") is not supported.");
        }
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
