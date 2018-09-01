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

    public static byte[] hash(HashAlgorithm algorithm, byte[]... inputs) {
        return hash(algorithm.getName(), inputs);
    }

    private static byte[] hash(String algorithm, byte[]... inputs) throws RuntimeException {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm, "SC"); // It's SpongyCastle on Android
            for (final byte[] input : inputs) {
                digest.update(input);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Hashing error: " + e.getMessage(), e);
        }
    }
}
