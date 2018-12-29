package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.ByteUtils;

/**
 * A signer on Curve448 of Edwards-CURVE DSA.
 *
 * @author halu5071 (Yasunori Horii)
 */
class Ed448Signer implements EdDsaSigner {

    private static final Curve CURVE = Curve448.getInstance();

    private final HashAlgorithm algorithm;
    private final SchemeProvider scheme;

    Ed448Signer(HashAlgorithm algorithm, SchemeProvider scheme) {
        this.algorithm = algorithm;
        this.scheme = scheme;
    }

    /**
     * Sign your message on your key pair.
     * <p>
     * You can set null value on context byte array. If you do that, Edwards set
     * zero-length byte array to context.
     *
     * @param keyPair {@link KeyPair} you want to use.
     * @param data    byte data you want to sign.
     * @param context byte array you want to use on signature.
     * @return {@link Signature} which has result in byte array.
     * @throws IllegalStateException if you input context which has 256 or above length.
     */
    @Override
    public Signature sign(KeyPair keyPair, byte[] data, byte[] context) {
        if (context == null) {
            context = new byte[0];
        }

        if (context.length > 255) {
            throw new IllegalStateException("context length in byte must be less than 255 bit.");
        }

        byte[] h = Hashes.hash(algorithm, 114, keyPair.getPrivateKey().getRaw());

        byte[] first57 = ByteUtils.split(h, 57)[0];
        first57[0] &= 0xFC;
        first57[56] &= 0x00;
        first57[55] |= 0x80;

        // Step3
        byte[] reversed = ByteUtils.reverse(first57);
        BigInteger s = new BigInteger(reversed);

        byte[] prefix = ByteUtils.split(h, 57)[1];

        byte[] rSeed = Hashes.hash(algorithm, 114, scheme.dom(context), prefix, data);
        byte[] rSeedReversed = ByteUtils.reverse(rSeed);
        BigInteger r = new BigInteger(1, rSeedReversed).mod(CURVE.getPrimeL());

        Point pointR = CURVE.getBasePoint().scalarMultiply(r);
        byte[] rPoint = pointR.encode().getValue();

        byte[] kSeed = Hashes.hash(algorithm, 114, scheme.dom(context), rPoint, keyPair.getPublicKey().getRaw(), data);

        BigInteger k = new BigInteger(1, ByteUtils.reverse(kSeed));

        BigInteger pointS = k.mod(CURVE.getPrimeL()).multiply(s).add(r).mod(CURVE.getPrimeL());
        byte[] sPoint = new CoordinateEd448(pointS).encode().getValue();

        return new SignatureEd448(ByteUtils.paddingZeroOnTail(rPoint, 57),
                ByteUtils.paddingZeroOnTail(sPoint, 57));
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, byte[] context, Signature signature) {
        try {
            if (context == null) {
                context = new byte[0];
            }
            byte[] rSeed = signature.getR();
            EncodedPoint encodedR = new EncodedPointEd448(rSeed);
            Point r = encodedR.decode();

            EncodedPoint encodedPublicKey = new EncodedPointEd448(keyPair.getPublicKey().getRaw());
            Point a = encodedPublicKey.decode();

            EncodedCoordinate encodedS = new EncodedCoordinateEd448(signature.getS());
            BigInteger s = encodedS.decode().getInteger();
            if (s.compareTo(BigInteger.ZERO) < 0 || s.compareTo(CURVE.getPrimeL()) > 0) {
                return false;
            }

            byte[] kSeed = Hashes.hash(algorithm, 114, scheme.dom(context), r.encode().getValue(), a.encode().getValue(), data);

            BigInteger k = new EncodedCoordinateEd448(kSeed).decode().getInteger();

            Point checkPoint = r.add(a.scalarMultiply(k));

            Point target = CURVE.getBasePoint().scalarMultiply(s);

            return checkPoint.isEqual(target);
        } catch (DecodeException e) {
            return false;
        }
    }
}
