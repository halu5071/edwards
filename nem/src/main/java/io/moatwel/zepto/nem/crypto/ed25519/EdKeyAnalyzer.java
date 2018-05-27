package io.moatwel.zepto.nem.crypto.ed25519;

import io.moatwel.zepto.nem.crypto.KeyAnalyzer;
import io.moatwel.zepto.nem.crypto.PublicKey;

public class EdKeyAnalyzer implements KeyAnalyzer {
    @Override
    public boolean isKeyCompressed(PublicKey publicKey) {
        return false;
    }
}
