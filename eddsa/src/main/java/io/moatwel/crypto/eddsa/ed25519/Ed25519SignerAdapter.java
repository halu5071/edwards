package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.SignerAdapter;
import io.moatwel.util.ByteUtils;

public class Ed25519SignerAdapter implements SignerAdapter {

    private final Ed25519Curve curve;

    public Ed25519SignerAdapter(Ed25519Curve curve) {
        this.curve = curve;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        byte[] h = Hashes.sha3Hash512(keyPair.getPrivateKey().getRaw());
        byte[] first = ByteUtils.split(h, h.length / 2)[0];
        first[0] = (byte)(first[0] & 0xF8);

        return null;
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return false;
    }
}
