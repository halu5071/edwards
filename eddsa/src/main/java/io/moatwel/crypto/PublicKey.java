package io.moatwel.crypto;

import java.math.BigInteger;

import io.moatwel.util.HexEncoder;

/**
 * PublicKey for EdDsa.
 *
 * @author halu5071 (Yasunori Horii)
 */
public class PublicKey {

    private final byte[] value;

    public PublicKey(BigInteger integer) {
        this(integer.toByteArray());
    }

    public PublicKey(byte[] bytes) {
        this.value = bytes;
    }

    public static PublicKey fromHexString(String hex) {
        try {
            return new PublicKey(HexEncoder.getBytes(hex));
        } catch (NumberFormatException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getRaw() {
        return this.value;
    }

    public String getHexString() {
        return HexEncoder.getString(value);
    }
}
