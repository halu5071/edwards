package io.moatwel.zepto.nem.crypto.ed25519;

import java.security.SecureRandom;

import io.moatwel.zepto.nem.crypto.KeyGenerator;
import io.moatwel.zepto.nem.crypto.KeyPair;
import io.moatwel.zepto.nem.crypto.PrivateKey;
import io.moatwel.zepto.nem.crypto.PublicKey;
import io.moatwel.zepto.nem.utils.ArrayUtils;

public class EdKeyGenerator implements KeyGenerator {

    private final SecureRandom random;

    public EdKeyGenerator() {
        this.random = new SecureRandom();
    }

    @Override
    public KeyPair generateKeyPair() {
        final byte[] seed = new byte[32];
        this.random.nextBytes(seed);

        final PrivateKey privateKey = new PrivateKey(ArrayUtils.toBigInteger(seed));

        return new KeyPair(privateKey, new EdCryptoEngine());
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey privateKey) {
        return null;
    }
}
