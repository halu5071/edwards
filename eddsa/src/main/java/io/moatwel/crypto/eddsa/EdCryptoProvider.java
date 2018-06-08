package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.BlockCipher;
import io.moatwel.crypto.CryptoProvider;
import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.KeyAnalyzer;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;

public class EdCryptoProvider implements CryptoProvider {

    private Curve curve;

    public EdCryptoProvider(Curve curve) {
        this.curve = curve;
    }

    @Override
    public Curve getCurve() {
        return curve;
    }

    @Override
    public DsaSigner createDsaSigner(KeyPair keyPair) {
        return new EdDsaSigner(keyPair);
    }

    @Override
    public KeyGenerator createKeyGenerator() {
        return new EdDsaKeyGenerator(curve, this);
    }

    @Override
    public BlockCipher createBlockCipher(KeyPair senderKeyPair, KeyPair recipientKeyPair) {
        return new EdBlockCipher(senderKeyPair, recipientKeyPair);
    }

    @Override
    public KeyAnalyzer createKeyAnalyzer() {
        return new EdKeyAnalyzer(curve);
    }
}
