package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
public class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private Curve448 curve = Curve448.getInstance();

    private HashAlgorithm hashAlgorithm;

    public Ed448PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        return new byte[0];
    }
}
