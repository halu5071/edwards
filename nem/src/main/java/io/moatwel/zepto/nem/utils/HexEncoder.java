package io.moatwel.zepto.nem.utils;

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
        final String paddedHexString = 0 == hexString.length() % 2 ? hexString : "0" + hexString;
        return Hex.decode(paddedHexString);
    }

    public static String getString(final byte[] bytes) {
        return Hex.toHexString(bytes);
    }
}
