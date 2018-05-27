package io.moatwel.zepto.nem.crypto;

public interface KeyGenerator {

    KeyPair generateKeyPair();

    PublicKey derivePublicKey(PrivateKey privateKey);
}
