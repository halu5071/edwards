package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * Delegate class from {@link io.moatwel.crypto.eddsa.EdDsaKeyGenerator}.
 * This will be provide from {@link Ed25519SchemeProvider}
 *
 * @author halu5071 (Yasunori Horii) 2018/6/8
 * @see Ed25519SchemeProvider
 */
class Ed25519PublicKeyDelegate implements PublicKeyDelegate {

    private Curve25519 curve = Curve25519.getInstance();

    private HashAlgorithm hashAlgorithm;

    Ed25519PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
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

        Point point = curve.getBasePoint().scalarMultiply(s);
        byte[] aX = point.getX().getInteger().toByteArray();
        byte[] aY = point.getY().getInteger().toByteArray();

        // Step4
        byte[] reversedY = ByteUtils.reverse(aY);
        int lengthX = aX.length;
        int lengthY = reversedY.length;
        int writeBit = aX[lengthX - 1] & 0b00000001;

        if (writeBit == 1) {
            reversedY[lengthY - 1] |= 1 << 7;
        } else {
            writeBit = ~(1 << 7);
            reversedY[lengthY - 1] &= writeBit;
        }

        return ByteUtils.paddingZeroOnTail(reversedY, 32);
    }
}
