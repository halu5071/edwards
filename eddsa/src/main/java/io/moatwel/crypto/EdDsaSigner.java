package io.moatwel.crypto;

/**
 * A interface represent signer for Edward-curve DSA.
 *
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 * @see io.moatwel.crypto.eddsa.ed25519.Ed25519Signer
 * @see io.moatwel.crypto.eddsa.ed448.Ed448Signer
 */
public interface EdDsaSigner {

    Signature sign(KeyPair keyPair, final byte[] data);

    boolean verify(KeyPair keyPair, final byte[] data, final Signature signature);
}
