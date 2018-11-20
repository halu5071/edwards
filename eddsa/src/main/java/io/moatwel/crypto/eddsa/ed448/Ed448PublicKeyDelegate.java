package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
class Ed448PublicKeyDelegate implements PublicKeyDelegate {

    private Curve448 curve = Curve448.getInstance();

    private HashAlgorithm hashAlgorithm;

    Ed448PublicKeyDelegate(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        // Step1
        byte[] hash = Hashes.hash(hashAlgorithm, privateKey.getRaw(), 114);
        byte[] first57 = ByteUtils.split(hash, 57)[0];

        // Step2
        first57[0] &= 0xFC;
        first57[56] &= 0x00;
        first57[55] |= 0x80;

        // Step3
        byte[] reversed = ByteUtils.reverse(first57);
        BigInteger s = new BigInteger(reversed);

        // Step4
        Point point = curve.getBasePoint().scalarMultiply(s);
        byte[] aX = point.getX().getInteger().toByteArray();
        byte[] aY = point.getY().getInteger().toByteArray();

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

        return ByteUtils.paddingZeroOnTail(reversed, curve.getPublicKeyByteLength());
    }
}
