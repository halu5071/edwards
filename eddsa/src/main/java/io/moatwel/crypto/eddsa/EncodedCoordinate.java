package io.moatwel.crypto.eddsa;

public abstract class EncodedCoordinate {

    protected byte[] value;

    public byte[] getValue() {
        return value;
    }

    /**
     * Encode value to Coordinate.
     *
     * All values on Edwards-curve can be encoded and decoded. The method is depends on
     * each schemes.
     *
     * @return Coordinate decoded.
     */
    public abstract Coordinate decode();
}
