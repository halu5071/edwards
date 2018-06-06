package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EdCryptoProvider;

public class Cipher implements BlockCipher {

    private final BlockCipher cipher;

    public Cipher(KeyPair senderKeyPair, KeyPair recipientKeyPair, Curve curve) {
        this(senderKeyPair, recipientKeyPair, new EdCryptoProvider(curve));
    }

    public Cipher(KeyPair senderKeyPair, KeyPair recipientKeyPair, CryptoProvider cryptoEngine) {
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
