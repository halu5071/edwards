package io.moatwel.crypto;

/**
 * A interface represent signer for Edward-curve DSA.
 *
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 */
public interface EdDsaSigner {

    Signature sign(KeyPair keyPair, final byte[] data, byte[] context);

    boolean verify(KeyPair keyPair, final byte[] data, byte[] context, final Signature signature);
}
