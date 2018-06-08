package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.util.ByteUtils;

public class EdDsaSigner implements DsaSigner {

    private final KeyPair keyPair;

    public EdDsaSigner(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    @Override
    public Signature sign(byte[] data) {
        byte[] h = Hashes.sha3Hash512(keyPair.getPrivateKey().getRaw());
        byte[] first32 = ByteUtils.split(h, h.length / 2)[0];
        first32[0] = (byte)(first32[0] & 0xF8);

        return null;
    }

    @Override
    public boolean verify(byte[] data, Signature signature) {
        return false;
    }

    @Override
    public boolean isCanonicalSignature(Signature signature) {
        return false;
    }

    @Override
    public Signature makeSignatureCanonical(Signature signature) {
        return null;
    }
}
