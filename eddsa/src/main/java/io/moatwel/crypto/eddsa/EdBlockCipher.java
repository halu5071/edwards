package io.moatwel.crypto.eddsa;

import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.PKCS7Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;
import java.util.Arrays;

import io.moatwel.crypto.BlockCipher;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;

public class EdBlockCipher implements BlockCipher {

    private KeyPair senderKeyPair;
    private KeyPair recipientKeyPair;
    private SecureRandom secureRandom;
    private int keyLength;

    public EdBlockCipher(KeyPair senderKeyPair, KeyPair recipientKeyPair) {
        this.senderKeyPair = senderKeyPair;
        this.recipientKeyPair = recipientKeyPair;
        this.secureRandom = new SecureRandom();
        this.keyLength = recipientKeyPair.getPublicKey().getRaw().length;
    }

    @Override
    public byte[] encrypt(byte[] input) {
        byte[] salt = new byte[this.keyLength];
        this.secureRandom.nextBytes(salt);

        byte[] sharedKey = this.getSharedKey(senderKeyPair.getPrivateKey(), recipientKeyPair.getPublicKey(), salt);

        byte[] ivData = new byte[16];
        this.secureRandom.nextBytes(ivData);

        BufferedBlockCipher cipher = setupBlockCipher(sharedKey, ivData, true);

        byte[] buf = transform(cipher, input);
        if (buf == null) {
            return null;
        }
        byte[] result = new byte[salt.length + ivData.length + buf.length];

        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(ivData, 0, result, salt.length, ivData.length);
        System.arraycopy(buf, 0, result, salt.length + ivData.length, buf.length);
        return result;
    }

    @Override
    public byte[] decrypt(byte[] input) {
        if (input.length < 64) {
            return null;
        }
        byte[] salt = Arrays.copyOfRange(input, 0, keyLength);
        byte[] ivData = Arrays.copyOfRange(input, keyLength, 48);
        byte[] encData = Arrays.copyOfRange(input, 48, input.length);

        byte[] sharedKey = getSharedKey(recipientKeyPair.getPrivateKey(), senderKeyPair.getPublicKey(), salt);

        BufferedBlockCipher cipher = setupBlockCipher(sharedKey, ivData, false);

        return transform(cipher, encData);
    }

    private byte[] transform(BufferedBlockCipher cipher, byte[] input) {
        byte[] buf = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, buf, 0);
        try {
            length += cipher.doFinal(buf, length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return null;
        }

        return Arrays.copyOf(buf, length);
    }

    private BufferedBlockCipher setupBlockCipher(byte[] sharedKey, byte[] ivData, boolean forEncryption) {
        KeyParameter param = new KeyParameter(sharedKey);
        CipherParameters cipherParameters = new ParametersWithIV(param, ivData);

        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
        cipher.reset();
        cipher.init(forEncryption, cipherParameters);
        return cipher;
    }

    private byte[] getSharedKey(PrivateKey senderPrivateKey, PublicKey recipientPublicKey, byte[] salt) {
        return null;
    }
}
