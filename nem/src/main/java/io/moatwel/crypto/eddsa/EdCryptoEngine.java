package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.BlockCipher;
import io.moatwel.crypto.CryptoEngine;
import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.KeyAnalyzer;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

public class EdCryptoEngine implements CryptoEngine {
    @Override
    public Curve getCurve() {
        return Ed25519Curve.getEdCurve();
    }

    @Override
    public DsaSigner createDsaSigner(KeyPair keyPair) {
        return new EdDsaSigner(keyPair);
    }

    @Override
    public KeyGenerator createKeyGenerator() {
        return new EdDsaKeyGenerator(Ed25519Curve.getEdCurve(), new EdCryptoEngine());
    }

    @Override
    public BlockCipher createBlockCipher(KeyPair senderKeyPair, KeyPair recipientKeyPair) {
        return new EdBlockCipher(senderKeyPair, recipientKeyPair);
    }

    @Override
    public KeyAnalyzer createKeyAnalyzer() {
        return new EdKeyAnalyzer(Ed25519Curve.getEdCurve());
    }
}
