package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Curve;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed448Signer implements EdDsaSigner {

    private static final Curve curve = Curve448.getInstance();

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        return null;
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return false;
    }
}
