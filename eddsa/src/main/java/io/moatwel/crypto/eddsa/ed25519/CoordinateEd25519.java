package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
public class CoordinateEd25519 extends Coordinate {

    public CoordinateEd25519(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("Coordinate byte must have 32 byte length");
        }

        this.value = value;
    }

    public CoordinateEd25519(BigInteger integer) {
        this(integer.toByteArray());
    }
}
