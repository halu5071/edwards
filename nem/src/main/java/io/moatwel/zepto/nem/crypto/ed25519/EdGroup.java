package io.moatwel.zepto.nem.crypto.ed25519;

import java.math.BigInteger;

public class EdGroup {

    public static final BigInteger GROUP_ORDER = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));

    public static EdGroupElement BASE_POINT;

//    static {
//        try {
//            BASE_POINT = getBasePoint();
//        } catch (Throwable t) {
//            t.printStackTrace();
//        }
//    }
//
//    private static EdGroupElement getBasePoint() {
//
//    }
}
