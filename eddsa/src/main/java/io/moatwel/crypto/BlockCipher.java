package io.moatwel.crypto;

public interface BlockCipher {

    byte[] encrypt(byte[] input);

    byte[] decrypt(byte[] input);
}
