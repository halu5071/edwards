package io.moatwel.crypto.eddsa.ed25519;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.ByteUtils;

/**
 * A Signer on Edwards-curve DSA specified on Ed25519 curve.
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/11
 * @see Ed25519Provider
 * @see EdDsaSigner
 */
public class Ed25519Signer implements EdDsaSigner {

    private static final Curve curve = Ed25519Curve.getCurve();

    @Override
    public Signature sign(KeyPair keyPair, byte[] data) {
        byte[] h = Hashes.sha3Hash512(keyPair.getPrivateKey().getRaw());
        byte[] first = ByteUtils.split(h, h.length / 2)[0];
        first[0] = (byte) (first[0] & 0xF8);
        first[31] |= 0b1000000;
        first[31] = (byte) (first[31] & ~(1 << 8));

        byte[] prefix = ByteUtils.split(h, h.length / 2)[1];

        byte[] rSeed = Hashes.sha3Hash512(prefix, data);
        byte[] rSeedReversed = ByteUtils.reverse(rSeed);
        String hex = Hex.encodeHexString(rSeed);
        BigInteger r = new BigInteger(rSeedReversed);

        // Step3
        BigInteger x = r.mod(curve.getPrimeL())
                .multiply(curve.getBasePoint().getX().getInteger())
                .mod(curve.getPrimeL());
        byte[] byteX = x.toByteArray();
        BigInteger y = r.mod(curve.getPrimeL())
                .multiply(curve.getBasePoint().getY().getInteger())
                .mod(curve.getPrimeL());
        byte[] byteY = y.toByteArray();
        byte[] rPoint = new PointEd25519(new CoordinateEd25519(byteX), new CoordinateEd25519(byteY)).encode().getValue();

        // Step4
        byte[] kSeed = Hashes.sha3Hash512(rPoint, keyPair.getPublicKey().getRaw(), data);
//        byte[] kSeedReversed = ByteUtils.reverse(kSeed);

        // Step5
        byte[] sSeed = ByteUtils.reverse(first);
        BigInteger k = new BigInteger(kSeed);
        BigInteger s = new BigInteger(sSeed);

        byte[] S = k.mod(curve.getPrimeL()).multiply(s).add(r).mod(curve.getPrimeL()).toByteArray();

        // Step6
        return new SignatureEd25519(rPoint, S);
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

//    private byte[] getByteArrayLength32(byte[] input) {
//        if (input[0] == 0) {
//            byte[] tmp = new byte[]
//        }
//    }
}
