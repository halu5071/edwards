package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;

public class Ed25519PublicKeyDelegate implements PublicKeyDelegate {

    private Ed25519Curve curve = Ed25519Curve.getCurve();

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        byte[] h = Hashes.sha3Hash512(privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(first32);
        BigInteger aXX = s.mod(curve.getPrimePowerP())
                .multiply(curve.getBasePoint().getX().getInteger())
                .mod(curve.getPrimePowerP());
        byte[] aX = s.mod(curve.getPrimePowerP())
                .multiply(curve.getBasePoint().getX().getInteger())
                .mod(curve.getPrimePowerP())
                .toByteArray();
        byte[] aY = s.mod(curve.getPrimePowerP())
                .multiply(curve.getBasePoint().getY().getInteger())
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
}
