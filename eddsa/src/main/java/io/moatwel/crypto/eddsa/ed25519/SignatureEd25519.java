package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/21
 */
class SignatureEd25519 extends Signature {

    SignatureEd25519(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }
}
