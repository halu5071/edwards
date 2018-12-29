package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * Signature for Ed448.
 *
 * @author halu5071 (Yasunori Horii)
 */
class SignatureEd448 extends Signature {

    SignatureEd448(BigInteger r, BigInteger s) {
        this(ArrayUtils.toByteArray(r, 57), ArrayUtils.toByteArray(s, 57));
    }

    SignatureEd448(byte[] byteR, byte[] byteS) {
        super(byteR, byteS);
        if (byteR.length != 57 || byteS.length != 57) {
            throw new IllegalArgumentException("Signature on ed448 curve must have 57 byte length.");
        }
    }

    SignatureEd448(byte[] sig) {
        this(ByteUtils.split(sig, 57)[0], ByteUtils.split(sig, 57)[1]);
    }
}
