package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/21
 */
class SignatureEd25519 extends Signature {

    SignatureEd25519(BigInteger r, BigInteger s) {
        this(ArrayUtils.toByteArray(r, 32), ArrayUtils.toByteArray(s, 32));
    }

    SignatureEd25519(byte[] byteR, byte[] byteS) {
        super(byteR, byteS);
        if (byteR.length != 32 || byteS.length != 32) {
            throw new IllegalArgumentException("Signature on Curve25519 must have 32 byte length.");
        }
    }

    SignatureEd25519(byte[] sig) {
        this(ByteUtils.split(sig, 32)[0], ByteUtils.split(sig, 32)[1]);
    }
}
