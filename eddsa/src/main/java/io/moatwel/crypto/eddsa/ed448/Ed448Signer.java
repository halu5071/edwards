package io.moatwel.crypto.eddsa.ed448;

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
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.ByteUtils;

import java.math.BigInteger;

/**
 * A signer on Curve448 of Edwards-CURVE DSA.
 *
 * @author halu5071 (Yasunori Horii)
 */
public class Ed448Signer implements EdDsaSigner {

    private static final Curve CURVE = Curve448.getInstance();

    private final HashAlgorithm algorithm;
    private final SchemeProvider scheme;

    public Ed448Signer(HashAlgorithm algorithm, SchemeProvider scheme) {
        this.algorithm = algorithm;
        this.scheme = scheme;
    }

    @Override
    public Signature sign(KeyPair keyPair, byte[] data, byte[] context) {
        context = beNonNullContext(context);
        checkContextLength(context);

        PublicKeyDelegate delegate = scheme.getPublicKeyDelegate();
        byte[] h = delegate.hashPrivateKey(keyPair.getPrivateKey());

        BigInteger s = keyPair.getPrivateKey().getScalarSeed(delegate);

        byte[] dom = scheme.dom(context);
        byte[] prefix = ByteUtils.split(h, 57)[1];
        byte[] ph = scheme.preHash(data);

        byte[] rSeed = Hashes.hash(algorithm, 114, dom, prefix, ph);
        byte[] rSeedReversed = ByteUtils.reverse(rSeed);
        BigInteger r = new BigInteger(1, rSeedReversed).mod(CURVE.getPrimeL());

        Point pointR = CURVE.getBasePoint().scalarMultiply(r);
        byte[] rPoint = pointR.encode().getValue();

        byte[] kSeed = Hashes.hash(algorithm, 114, dom, rPoint, keyPair.getPublicKey().getRaw(), ph);

        BigInteger k = new BigInteger(1, ByteUtils.reverse(kSeed));

        BigInteger pointS = k.mod(CURVE.getPrimeL()).multiply(s).add(r).mod(CURVE.getPrimeL());
        byte[] sPoint = new CoordinateEd448(pointS).encode().getValue();

        return new SignatureEd448(ByteUtils.paddingZeroOnTail(rPoint, 57),
                ByteUtils.paddingZeroOnTail(sPoint, 57));
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, byte[] context, Signature signature) {
        try {
            context = beNonNullContext(context);
            checkContextLength(context);

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

            byte[] dom = scheme.dom(context);
            byte[] ph = scheme.preHash(data);
            byte[] kSeed = Hashes.hash(algorithm, 114, dom, r.encode().getValue(), a.encode().getValue(), ph);

            BigInteger k = new EncodedCoordinateEd448(kSeed).decode().getInteger();

            Point checkPoint = r.add(a.scalarMultiply(k));

            Point target = CURVE.getBasePoint().scalarMultiply(s);

            return checkPoint.isEqual(target);
        } catch (DecodeException e) {
            return false;
        }
    }

    private byte[] beNonNullContext(byte[] context) {
        if (context == null) context = new byte[0];
        return context;
    }

    private void checkContextLength(byte[] context) {
        if (context.length > 255)
            throw new IllegalStateException("context length in byte must be less than 256 bytes.");
    }
}
