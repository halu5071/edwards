package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.Signature;
import io.moatwel.util.ArrayUtils;

class SignatureEd448 extends Signature {

    SignatureEd448(byte[] r, byte[] s) {
        if (r.length != 57 || s.length != 57) {
            throw new IllegalArgumentException("r and s must have 57 byte length on Ed448 Curve");
        }

        this.r = r;
        this.s = s;
    }

    SignatureEd448(BigInteger r, BigInteger s) {
        this(r.toByteArray(), s.toByteArray());
    }

    SignatureEd448(byte[] value) {
        this(ArrayUtils.split(value, 57)[0], ArrayUtils.split(value, 57)[1]);
    }
}
