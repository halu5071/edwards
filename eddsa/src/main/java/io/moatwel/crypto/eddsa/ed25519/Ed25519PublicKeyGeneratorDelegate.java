package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyGeneratorDelegate;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

public class Ed25519PublicKeyGeneratorDelegate implements PublicKeyGeneratorDelegate {

    private Ed25519Curve curve;

    Ed25519PublicKeyGeneratorDelegate(Ed25519Curve curve) {
        this.curve = curve;
    }

    @Override
    public byte[] generatePublicKeySeed(PrivateKey privateKey) {
        byte[] h = Hashes.sha3Hash512(privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] = (byte)(first32[0] & 0xF8);
        first32[31] |= 0b1000000;
        first32[31] = (byte)(first32[31] & ~(1 << 8));

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);
        byte[] aX = getACoordinate(new BigInteger(curve.getBasePoint().getX().getValue()).multiply(s));
        byte[] aY = getACoordinate(new BigInteger(curve.getBasePoint().getY().getValue()).multiply(s));

        // Step4
        byte[] reversedY = ByteUtils.reverse(aY);
        int lengthX = aX.length;
        int lengthY = reversedY.length;
        int writeBit = aX[lengthX - 1] & 1;
        reversedY[lengthY - 1] |= writeBit;

        return reversedY;
    }

    private byte[] getACoordinate(BigInteger integer) {
        return integer.mod(curve.getPrimePowerP()).toByteArray();
    }
}
