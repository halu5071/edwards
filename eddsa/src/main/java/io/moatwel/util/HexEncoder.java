package io.moatwel.util;

import org.spongycastle.util.encoders.Hex;

public class HexEncoder {

    public static byte[] getBytes(final String hexString) {
        byte[] b = new byte[hexString.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hexString.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String getString(final byte[] bytes) {
        return Hex.toHexString(bytes);
    }
}
