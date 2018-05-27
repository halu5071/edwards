package io.moatwel.zepto.nem.crypto;

import io.moatwel.zepto.nem.crypto.ed25519.EdCryptoEngine;

public class Cipher implements BlockCipher {

    private final BlockCipher cipher;

    public Cipher(KeyPair senderKeyPair, KeyPair recipientKeyPair) {
        this(senderKeyPair, recipientKeyPair, new EdCryptoEngine());
    }

    public Cipher(KeyPair senderKeyPair, KeyPair recipientKeyPair, CryptoEngine cryptoEngine) {
        this(cryptoEngine.createBlockCipher(senderKeyPair, recipientKeyPair));
    }

    public Cipher(BlockCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public byte[] encrypt(byte[] input) {
        return cipher.encrypt(input);
    }

    @Override
    public byte[] decrypt(byte[] input) {
        return cipher.decrypt(input);
    }
}
