package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

import java.math.BigInteger;

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
        if (!(privateKey instanceof PrivateKeyEd25519)) {
            throw new IllegalArgumentException("Public key on Curve25519 must be " +
                    CURVE.getPublicKeyByteLength() + " byte length. Length: " + privateKey.getRaw().length);
        }

        BigInteger s = privateKey.getScalarSeed(this);

        Point point = CURVE.getBasePoint().scalarMultiply(s);
        return point.encode().getValue();
    }

    @Override
    public byte[] hashPrivateKey(PrivateKey privateKey) {
        return Hashes.hash(hashAlgorithm, privateKey.getRaw());
    }
}
