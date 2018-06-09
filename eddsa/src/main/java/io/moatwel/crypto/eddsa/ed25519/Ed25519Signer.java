package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;

public class Ed25519Signer implements DsaSigner {

    private static final Curve curve = Ed25519Curve.getCurve();

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        // Step1
        PrivateKey privateKey = keyPair.getPrivateKey();
        byte[] h = Hashes.sha3Hash256(privateKey.getRaw());
        byte[] first32 = ByteUtils.split(h, 32)[0];
        byte[] prefix = ByteUtils.split(h, 32)[1];

        // Step2
        first32[0] = (byte)(first32[0] & 0xF8);
        first32[31] |= 0b1000000;
        first32[31] = (byte)(first32[31] & ~(1 << 8));

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        byte[] rSeed = Hashes.sha3Hash512(ByteUtils.join(prefix, data));
        BigInteger r = new BigInteger(ByteUtils.reverse(rSeed));

        byte[] aX = getCoordinate(new BigInteger(curve.getBasePoint().getX().getValue()).multiply(r));
        byte[] aY = getCoordinate(new BigInteger(curve.getBasePoint().getY().getValue()).multiply(r));

        Point point = new Point(new Coordinate(aX), new Coordinate(aY));
        point.encode();

        return null;
    }

    private byte[] getCoordinate(BigInteger integer) {
        return integer.mod(curve.getPrimePowerP()).toByteArray();
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return false;
    }

    @Override
    public boolean isCanonicalSignature(Signature signature) {
        return false;
    }

    @Override
    public Signature makeSignatureCanonical(Signature signature) {
        return null;
    }
}
