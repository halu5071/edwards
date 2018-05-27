package io.moatwel.zepto.nem.crypto;

public interface BlockCipher {

    byte[] encrypt(byte[] input);

    byte[] decrypt(byte[] input);
}
