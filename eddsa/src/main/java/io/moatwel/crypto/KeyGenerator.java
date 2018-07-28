package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.EdKeyAnalyzer;

public interface KeyGenerator {

    EdKeyAnalyzer getKeyAnalyzer();

    /**
     * @return {@link KeyPair} generate from random source.
     */
    KeyPair generateKeyPair();

    /**
     * generate {@link KeyPair} from an existing {@link PrivateKey}.
     *
     * @param privateKey a seed of {@link KeyPair}
     * @return {@link KeyPair} generate from an existing {@link PrivateKey}
     */
    KeyPair generateKeyPair(PrivateKey privateKey);

    PublicKey derivePublicKey(PrivateKey privateKey);
}
