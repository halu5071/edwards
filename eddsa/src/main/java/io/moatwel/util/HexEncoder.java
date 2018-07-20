package io.moatwel.util;

import org.spongycastle.util.encoders.DecoderException;
import org.spongycastle.util.encoders.Hex;

public class HexEncoder {

    public static byte[] getBytes(final String hexString) {
        try {
            return getBytesInternal(hexString);
        } catch (final DecoderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] tryGetBytes(final String hexString) {
        try {
            return getBytesInternal(hexString);
        } catch (final DecoderException e) {
            return null;
        }
    }

    private static byte[] getBytesInternal(final String hexString) throws DecoderException {
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
