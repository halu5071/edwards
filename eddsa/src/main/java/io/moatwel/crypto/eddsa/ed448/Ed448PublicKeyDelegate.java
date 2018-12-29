package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

/**
 * Delegate class from {@link io.moatwel.crypto.eddsa.EdDsaKeyGenerator}.
 * This will be provide from {@link Ed448SchemeProvider}
 *
 * @author halu5071 (Yasunori Horii)
 * @see Ed448SchemeProvider
 */
class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private static final Curve448 CURVE = Curve448.getInstance();

    private final HashAlgorithm hashAlgorithm;

    Ed448PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        // Step1
        byte[] hash = Hashes.hash(hashAlgorithm, 114, privateKey.getRaw());
        byte[] first57 = ByteUtils.split(hash, 57)[0];

        // Step2
        first57[0] &= 0xFC;
        first57[56] &= 0x00;
        first57[55] |= 0x80;

        // Step3
        byte[] reversed = ByteUtils.reverse(first57);
        BigInteger s = new BigInteger(reversed);

        // Step4
        Point point = CURVE.getBasePoint().scalarMultiply(s);
        return point.encode().getValue();
    }
}
