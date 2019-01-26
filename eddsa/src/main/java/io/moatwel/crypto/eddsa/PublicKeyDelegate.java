package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.PrivateKey;

/**
 * Represent delegate class for generating {@link io.moatwel.crypto.PublicKey}
 *
 * @author Yasunori Horii
 */
public interface PublicKeyDelegate {

    /**
     * Return byte array which is a seed of {@link io.moatwel.crypto.PublicKey}
     *
     * @param privateKey {@link PrivateKey} which this publicKey derived from.
     * @return seed byte array for {@link io.moatwel.crypto.PublicKey}
     */
    byte[] generatePublicKeySeed(PrivateKey privateKey);
}
