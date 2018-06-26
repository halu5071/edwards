package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import javax.annotation.Nonnull;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

/**
 * Delegate class from {@link io.moatwel.crypto.eddsa.EdDsaKeyGenerator}.
 * This will be provide from {@link Ed25519Provider}
 *
 * @author halu5071 (Yasunori Horii) 2018/6/8
 * @see Ed25519Provider
 */
public class Ed25519PublicKeyDelegate implements PublicKeyDelegate {

    private Ed25519Curve curve = Ed25519Curve.getCurve();

    private HashAlgorithm hashAlgorithm;

    public Ed25519PublicKeyDelegate(@Nonnull HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        byte[] h = Hashes.hash(hashAlgorithm.getName(), privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        byte[] aX = s.mod(curve.getPrimePowerP())
                .multiply(curve.getBasePoint().getX().getInteger())
                .modInverse(curve.getPrimePowerP())
                .mod(curve.getPrimePowerP())
                .toByteArray();
        byte[] aY = s.mod(curve.getPrimePowerP())
                .multiply(curve.getBasePoint().getY().getInteger())
                .modInverse(curve.getPrimePowerP())
                .mod(curve.getPrimePowerP())
                .toByteArray();

        // Step4
        byte[] reversedY = ByteUtils.reverse(aY);
        int lengthX = aX.length;
        int lengthY = reversedY.length;
        int writeBit = aX[lengthX - 1] & 0b00000001;
        reversedY[lengthY - 1] |= 1 << writeBit;

        return reversedY;
    }

//    private byte[] generateScalarA(byte[] value) {
//
//    }
}
