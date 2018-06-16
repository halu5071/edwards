package io.moatwel.crypto.eddsa;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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

    public String asOctetString() {
        ByteBuffer buffer = ByteBuffer.wrap(value);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        return buffer.toString();
    }
}
