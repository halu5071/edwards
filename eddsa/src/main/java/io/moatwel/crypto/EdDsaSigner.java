package io.moatwel.crypto;

/**
 * A interface represent signer for Edward-curve DSA.
 *
 * @author halu5071 (Yasunori Horii)
 */
public interface EdDsaSigner {

    /**
     * Sign your message on your key pair.
     *
     * <p>
     * You can set null value on context byte array. If you do that, however, you must set
     * zero-length byte array to context.
     *
     * @param keyPair {@link KeyPair} you want to use.
     * @param data    byte data you want to sign.
     * @param context byte array you want to use on this signature.
     * @return {@link Signature} which has result in byte array.
     * @throws IllegalStateException if you input context which has 256 or above length.
     */
    Signature sign(KeyPair keyPair, final byte[] data, byte[] context);

    /**
     * Verify your message with signature on your key pair.
     *
     * <p>
     * Pay attention to use the same {@code context} as the context on signing.
     * <p>
     * Verify operation must handle point decoding, which throw
     * {@link io.moatwel.crypto.eddsa.DecodeException}. This method must tackle with that exception.
     * {@link io.moatwel.crypto.eddsa.DecodeException} means failure of verifying, so this method
     * must return false.
     *
     * @param keyPair {@link KeyPair} you want to use.
     * @param data byte array you want to verify.
     * @param context byte array you want to use on this signature.
     * @param signature {@link Signature} to verify you message.
     * @return true if {@code data} is authorized,
     *         false if not.
     */
    boolean verify(KeyPair keyPair, final byte[] data, byte[] context, final Signature signature);
}
