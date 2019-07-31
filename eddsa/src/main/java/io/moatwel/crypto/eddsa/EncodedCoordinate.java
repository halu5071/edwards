package io.moatwel.crypto.eddsa;

/**
 * Encoded Coordinate on Elliptic Curve.
 *
 * @author halu5071 (Yasunori Horii)
 */
public abstract class EncodedCoordinate {

    protected final byte[] value;

    protected EncodedCoordinate(byte[] value) {
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }

    /**
     * Encode value to Coordinate.
     * <p>
     * All values on Edwards-curve can be encoded and decoded. The method is depends on
     * each schemes.
     *
     * @return Coordinate decoded.
     */
    public abstract Coordinate decode();
}
