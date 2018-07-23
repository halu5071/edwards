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
        this.r = r;
        this.s = s;
    }
}
