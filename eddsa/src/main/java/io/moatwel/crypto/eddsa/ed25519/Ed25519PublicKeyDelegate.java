package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

/**
 * Delegate class from {@link io.moatwel.crypto.eddsa.EdDsaKeyGenerator}.
 * This will be provide from {@link Ed25519SchemeProvider}
 *
 * @author halu5071 (Yasunori Horii)
 * @see Ed25519SchemeProvider
 */
public class Ed25519PublicKeyDelegate implements PublicKeyDelegate {

    private static final Curve25519 CURVE = Curve25519.getInstance();

    private final HashAlgorithm hashAlgorithm;

    public Ed25519PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        byte[] h = Hashes.hash(hashAlgorithm, privateKey.getRaw());

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
}
