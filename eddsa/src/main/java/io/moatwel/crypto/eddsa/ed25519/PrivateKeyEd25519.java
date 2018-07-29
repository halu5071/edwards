package io.moatwel.crypto.eddsa.ed25519;

import java.security.SecureRandom;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.util.HexEncoder;

public class PrivateKeyEd25519 extends PrivateKey {

    private PrivateKeyEd25519(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("PrivateKey on ed25519 curve must have 32 byte length");
        }
        this.value = value;
    }

    public static PrivateKey fromHexString(String hexString) {
        return new PrivateKeyEd25519(HexEncoder.getBytes(hexString));
    }

    public static PrivateKey fromBytes(byte[] bytes) {
        return new PrivateKeyEd25519(bytes);
    }

    public static PrivateKey random() {
        byte[] seed = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        return new PrivateKeyEd25519(seed);
    }
}