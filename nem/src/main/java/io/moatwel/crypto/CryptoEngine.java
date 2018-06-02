package io.moatwel.crypto;

import io.moatwel.crypto.eddsa.Curve;

public interface CryptoEngine {

    Curve getCurve();

    DsaSigner createDsaSigner(KeyPair keyPair);

    KeyGenerator createKeyGenerator();

    BlockCipher createBlockCipher(KeyPair senderKeyPair, KeyPair recipientKeyPair);

    KeyAnalyzer createKeyAnalyzer();
}
