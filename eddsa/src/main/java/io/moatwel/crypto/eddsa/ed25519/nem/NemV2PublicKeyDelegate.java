package io.moatwel.crypto.eddsa.ed25519.nem;

import java.math.BigInteger;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import io.moatwel.util.ByteUtils;

public class NemV2PublicKeyDelegate implements PublicKeyDelegate {

    private static final Curve CURVE = Curve25519.getInstance();
    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA3_512;

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        if (!(privateKey instanceof PrivateKeyEd25519)) {
            throw new IllegalArgumentException("Public key on Curve25519 must be " +
                    CURVE.getPublicKeyByteLength() + " byte length. Length: " + privateKey.getRaw().length);
        }

        byte[] h = hashPrivateKey(privateKey);

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        Point point = CURVE.getBasePoint().scalarMultiply(s);
        return point.encode().getValue();
    }

    @Override
    public byte[] hashPrivateKey(PrivateKey privateKey) {
        return Hashes.hash(HASH_ALGORITHM, privateKey.getRaw());
    }
}
