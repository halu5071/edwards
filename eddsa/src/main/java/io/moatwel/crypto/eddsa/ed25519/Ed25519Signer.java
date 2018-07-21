package io.moatwel.crypto.eddsa.ed25519;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

/**
 * A Signer on Edwards-curve DSA specified on Ed25519 curve.
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/11
 * @see Ed25519Provider
 * @see EdDsaSigner
 */
public class Ed25519Signer implements EdDsaSigner {

    private static final Curve curve = Ed25519Curve.getCurve();

    private HashAlgorithm algorithm;

    Ed25519Signer(HashAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        byte[] h = Hashes.hash(algorithm, keyPair.getPrivateKey().getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step2
        byte[] prefix = ByteUtils.split(h, 32)[1];

        byte[] rSeed = Hashes.hash(algorithm, prefix, data);
        byte[] rSeedReversed = ByteUtils.reverse(rSeed);
        BigInteger r = new BigInteger(rSeedReversed);
        System.out.println("r: " + r.toString());

        // Step3
        Point pointR = curve.getBasePoint().scalarMultiply(r);
        System.out.println("Rx: " + pointR.getX().getInteger());
        System.out.println("Ry: " + pointR.getY().getInteger());
        byte[] rPoint = pointR.encode().getValue();  // この時点でうまく行ってない
        System.out.println("R byteHex: " + HexEncoder.getString(rPoint));

        // Step4
        byte[] kSeed = Hashes.hash(algorithm, rPoint, keyPair.getPublicKey().getRaw(), data);
        System.out.println("kSeed: " + HexEncoder.getString(kSeed));

        // Step5
        BigInteger k = new BigInteger(1, ByteUtils.reverse(kSeed));
        System.out.println("K: " + k);
        byte[] sSeed = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(sSeed);
        System.out.println("s: " + s.toString());

        byte[] sPoint = k.mod(curve.getPrimeL()).multiply(s).add(r).mod(curve.getPrimeL()).toByteArray();

        // Step6
        return new SignatureEd25519(rPoint, sPoint);
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
