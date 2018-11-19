package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private Curve448 curve = Curve448.getInstance();

    private HashAlgorithm hashAlgorithm;

    Ed448PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        byte[] hash = Hashes.hash(hashAlgorithm, privateKey.getRaw(), 114);

        byte[] first57 = ByteUtils.split(hash, 57)[0];
        return new byte[0];
    }
}
