package io.moatwel.crypto.eddsa;

public class EncodedPoint {

    private final byte[] value;

    public EncodedPoint(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("EncodedPoint must have 32 byte length.");
        }
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }
}
