package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/21
 */
class SignatureEd25519 extends Signature {

    SignatureEd25519(BigInteger r, BigInteger s) {
        this(ArrayUtils.toByteArray(r, 32), ArrayUtils.toByteArray(s, 32));
    }

    SignatureEd25519(byte[] byteR, byte[] byteS) {
        if (byteR.length != 32 || byteS.length != 32) {
            throw new IllegalArgumentException("Signature on Curve25519 must have 32 byte length.");
        }

        this.r = byteR;
        this.s = byteS;
    }
}
