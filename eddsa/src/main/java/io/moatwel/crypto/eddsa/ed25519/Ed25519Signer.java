package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashProvider;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ArrayUtils;
import io.moatwel.util.ByteUtils;

/**
 * A Signer on Edwards-curve DSA specified on Ed25519 curve.
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/11
 * @see Ed25519CurveProvider
 * @see EdDsaSigner
 */
public class Ed25519Signer implements EdDsaSigner {

    private static final Curve curve = Ed25519Curve.getCurve();

    private HashProvider hashProvider;

    Ed25519Signer(HashProvider hashProvider) {
        this.hashProvider = hashProvider;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        byte[] h = hashProvider.hash(keyPair.getPrivateKey().getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        byte[] sSeed = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(sSeed);

        // Step2
        byte[] prefix = ByteUtils.split(h, 32)[1];

        byte[] rSeed = hashProvider.hash(prefix, data);
        byte[] rSeedReversed = ByteUtils.reverse(rSeed);
        BigInteger r = new BigInteger(1, rSeedReversed);

        // Step3
        Point pointR = curve.getBasePoint().scalarMultiply(r);
        byte[] rPoint = pointR.encode().getValue();

        // Step4
        byte[] kSeed = hashProvider.hash(rPoint, keyPair.getPublicKey().getRaw(), data);

        // Step5
        BigInteger k = new BigInteger(1, ByteUtils.reverse(kSeed));

        BigInteger pointS = k.mod(curve.getPrimeL()).multiply(s).add(r).mod(curve.getPrimeL());
        byte[] sPoint = ArrayUtils.toByteArray(pointS, 32);

        // Step6
        return new SignatureEd25519(rPoint, sPoint);
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        byte[] rSeed = signature.getR();
        EncodedPoint encoded = new EncodedPointEd25519(rSeed);
        Point r = encoded.decode();

        EncodedPoint encodedPublicKey = new EncodedPointEd25519(keyPair.getPublicKey().getRaw());
        Point a = encodedPublicKey.decode();

        BigInteger s = new BigInteger(1, ByteUtils.reverse(signature.getS()));

        byte[] kSeed = hashProvider.hash(signature.getR(), keyPair.getPublicKey().getRaw(), data);
        BigInteger k = new BigInteger(1, kSeed);

        Point checkPoint = r.add(a.scalarMultiply(k));

        Point target = curve.getBasePoint().scalarMultiply(s);

        return checkPoint.isEqual(target);
    }
}
