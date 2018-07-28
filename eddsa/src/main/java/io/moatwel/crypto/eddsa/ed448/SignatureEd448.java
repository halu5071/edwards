package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
class SignatureEd448 extends Signature {

    SignatureEd448(BigInteger r, BigInteger s) {
        this(ArrayUtils.toByteArray(r, 57), ArrayUtils.toByteArray(s, 57));
    }

    SignatureEd448(byte[] byteR, byte[] byteS) {
        if (byteR.length != 57 || byteS.length != 57) {
            throw new IllegalArgumentException("Signature on ed448 curve must have 57 byte length.");
        }

        this.r = byteR;
        this.s = byteS;
    }
}
