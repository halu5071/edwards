package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;

/**
 * @author halu5071 (Yasunori Horii) at 2018/06/28
 */
public class CoordinateEd448 extends Coordinate {


    public CoordinateEd448(byte[] value) {
        if (value.length != 57) {
            throw new IllegalArgumentException("Coordinate byte must have 32 byte length");
        }

        this.value = value;
    }

    public CoordinateEd448(BigInteger integer) {
        this(integer.toByteArray());
    }
}
