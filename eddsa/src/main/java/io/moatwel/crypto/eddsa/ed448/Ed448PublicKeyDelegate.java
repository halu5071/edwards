package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * Delegate class from {@link io.moatwel.crypto.eddsa.EdDsaKeyGenerator}.
 * This will be provide from {@link Ed448SchemeProvider}
 *
 * @author halu5071 (Yasunori Horii)
 * @see Ed448SchemeProvider
 */
public class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private static final Curve448 CURVE = Curve448.getInstance();

    private final HashAlgorithm hashAlgorithm;

    public Ed448PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        if (!(privateKey instanceof PrivateKeyEd448)) {
            throw new IllegalArgumentException("Public key on Curve448 must be " +
                    CURVE.getPublicKeyByteLength() + " byte length. Length: " + privateKey.getRaw().length);
        }

        BigInteger s = privateKey.getScalarSeed(hashAlgorithm);

        Point point = CURVE.getBasePoint().scalarMultiply(s);
        return point.encode().getValue();
    }

    @Override
    public byte[] hashPrivateKey(PrivateKey privateKey) {
        return Hashes.hash(hashAlgorithm, 114, privateKey.getRaw());
    }
}
