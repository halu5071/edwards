package io.moatwel.zepto.nem.crypto;

public interface CryptoEngine {

    Curve getCurve();

    DsaSigner createDsaSigner(KeyPair keyPair);

    KeyGenerator createKeyGenerator();

    BlockCipher createBlockCipher(KeyPair senderKeyPair, KeyPair recipientKeyPair);

    KeyAnalyzer createKeyAnalyzer();
}
