package io.moatwel.zepto.nem.crypto.ed25519;

import java.math.BigInteger;

import io.moatwel.zepto.nem.crypto.Curve;

public class EdCurve implements Curve {

    private static final EdCurve ED_CURVE;

    static {
        ED_CURVE = new EdCurve();
    }

    @Override
    public String getName() {
        return "ed25519";
    }

    @Override
    public BigInteger getGroupOrder() {
        return null;
    }

    @Override
    public BigInteger getHalfGroupOrder() {
        return null;
    }

    public static EdCurve getEdCurve() {
        return ED_CURVE;
    }
}
