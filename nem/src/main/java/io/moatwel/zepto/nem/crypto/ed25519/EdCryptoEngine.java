package io.moatwel.zepto.nem.crypto.ed25519;

import io.moatwel.zepto.nem.crypto.BlockCipher;
import io.moatwel.zepto.nem.crypto.CryptoEngine;
import io.moatwel.zepto.nem.crypto.Curve;
import io.moatwel.zepto.nem.crypto.DsaSigner;
import io.moatwel.zepto.nem.crypto.KeyAnalyzer;
import io.moatwel.zepto.nem.crypto.KeyGenerator;
import io.moatwel.zepto.nem.crypto.KeyPair;

public class EdCryptoEngine implements CryptoEngine {
    @Override
    public Curve getCurve() {
        return EdCurve.getEdCurve();
    }

    @Override
    public DsaSigner createDsaSigner(KeyPair keyPair) {
        return null;
    }

    @Override
    public KeyGenerator createKeyGenerator() {
        return null;
    }

    @Override
    public BlockCipher createBlockCipher(KeyPair senderKeyPair, KeyPair recipientKeyPair) {
        return null;
    }

    @Override
    public KeyAnalyzer createKeyAnalyzer() {
        return null;
    }
}
