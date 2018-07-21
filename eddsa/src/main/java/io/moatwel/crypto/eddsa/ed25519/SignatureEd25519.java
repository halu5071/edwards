package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/21
 */
class SignatureEd25519 extends Signature {

    SignatureEd25519(byte[] r, byte[] s) {
        if (r.length > 32 || s.length > 32) {
            throw new IllegalArgumentException("r and s must have 32 byte length.");
        }
        this.r = r;
        this.s = s;
    }

    SignatureEd25519(BigInteger r, BigInteger s) {
        this(r.toByteArray(), s.toByteArray());
    }

    SignatureEd25519(byte[] bytes) {
        this(ArrayUtils.split(bytes, 32)[0], ArrayUtils.split(bytes, 32)[1]);
    }
}
