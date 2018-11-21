package io.moatwel.crypto;

import org.spongycastle.crypto.digests.SHAKEDigest;
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
        return hash(algorithm, algorithm.getDefaultBitLength() / 8, inputs);
    }

    public static byte[] hash(HashAlgorithm algorithm, int outputByteLength, byte[]... inputs) {
        switch (algorithm) {
            case SHAKE_128:
            case SHAKE_256:
                return hashVariableOutput(algorithm, outputByteLength, inputs);
            default:
                if (algorithm.getDefaultBitLength() / 8 == outputByteLength) {
                    return hash(algorithm.getName(), inputs);
                } else {
                    throw new IllegalStateException("Specified output byte length(" + outputByteLength + ") is not available.");
                }
        }
    }

    private static byte[] hash(String algorithm, byte[]... inputs) throws RuntimeException {
        MessageDigest digest;
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

    private static byte[] hashVariableOutput(HashAlgorithm algorithm, int byteLength, byte[]... inputs) {
        SHAKEDigest shakeDigest = new SHAKEDigest(algorithm.getDefaultBitLength());
        for (byte[] input : inputs) {
            shakeDigest.update(input, 0, input.length);
        }
        byte[] result = new byte[byteLength];
        shakeDigest.doFinal(result, 0, byteLength);
        return result;
    }
}
