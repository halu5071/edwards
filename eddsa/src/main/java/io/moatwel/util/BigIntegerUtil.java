package io.moatwel.util;

import java.math.BigInteger;

public class BigIntegerUtil {

    public static BigInteger toBigInteger(byte[] value) {
        return new BigInteger(value);
    }
}
