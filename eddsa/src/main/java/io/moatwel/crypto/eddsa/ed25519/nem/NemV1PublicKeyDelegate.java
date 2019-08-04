package io.moatwel.crypto.eddsa.ed25519.nem;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.ed25519.Ed25519PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

public class NemV1PublicKeyDelegate extends Ed25519PublicKeyDelegate {

    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.KECCAK_512;

    public NemV1PublicKeyDelegate() {
        super(HASH_ALGORITHM);
    }

    @Override
    public byte[] hashPrivateKey(PrivateKey privateKey) {
        return Hashes.hash(HASH_ALGORITHM, ByteUtils.reverse(privateKey.getRaw()));
    }
}
