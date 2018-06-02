package io.moatwel.crypto;

import io.moatwel.util.HexEncoder;

public class PublicKey {

    private final byte[] value;

    public PublicKey(byte[] bytes) {
        this.value = bytes;
    }

    public static PublicKey fromHexString(String hex) {
        try {
            return new PublicKey(HexEncoder.getBytes(hex));
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e);
        }
    }

    public byte[] getRaw() {
        return this.value;
    }
}
