package io.moatwel.crypto;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class Hashes {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] sha3Hash256(byte[]... inputs) {
        return hash("SHA3-256", inputs);
    }

    public static byte[] sha3Hash512(byte[]... inputs) {
        return hash("SHA3-512", inputs);
    }

    public static byte[] ripemd160(byte[]... inputs) {
        return hash("RIPEMD160", inputs);
    }

    private static byte[] hash(String algorithm, byte[]... inputs) throws CryptoException {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm, "SC");
            for (byte[] input: inputs) {
                digest.update(input);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException("Hashing error: " + e.getMessage(), e);
        }
    }
}
