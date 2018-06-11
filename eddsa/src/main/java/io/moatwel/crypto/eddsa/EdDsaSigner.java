package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.util.ByteUtils;

public class EdDsaSigner implements DsaSigner {

    private final Curve curve;

    public EdDsaSigner(Curve curve) {
        this.curve = curve;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        byte[] h = Hashes.sha3Hash512(keyPair.getPrivateKey().getRaw());
        byte[] first = ByteUtils.split(h, h.length / 2)[0];
        first[0] = (byte)(first[0] & 0xF8);

        return curve.getSignerDelegate().sign(keyPair, data);
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return curve.getSignerDelegate().verify(keyPair, data, signature);
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
