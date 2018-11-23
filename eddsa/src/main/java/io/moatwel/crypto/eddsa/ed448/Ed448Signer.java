package io.moatwel.crypto.eddsa.ed448;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

/**
 * @author halu5071 (Yasunori Horii) at 2018/6/26
 */
class Ed448Signer implements EdDsaSigner {

    private static final Curve curve = Curve448.getInstance();

    private HashAlgorithm algorithm;
    private SchemeProvider scheme;

    Ed448Signer(HashAlgorithm algorithm, SchemeProvider scheme) {
        this.algorithm = algorithm;
        this.scheme = scheme;
    }

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
        BigInteger r = new BigInteger(1, rSeedReversed).mod(curve.getPrimeL());

        Point pointR = curve.getBasePoint().scalarMultiply(r);
        byte[] rPoint = pointR.encode().getValue();

        byte[] kSeed = Hashes.hash(algorithm, 114, scheme.dom(context), rPoint, keyPair.getPublicKey().getRaw(), data);

        BigInteger k = new BigInteger(1, ByteUtils.reverse(kSeed));

        BigInteger pointS = k.mod(curve.getPrimeL()).multiply(s).add(r).mod(curve.getPrimeL());
        byte[] sPoint = new CoordinateEd448(pointS).encode().getValue();

        return new SignatureEd448(ByteUtils.paddingZeroOnTail(rPoint, 57),
                ByteUtils.paddingZeroOnTail(sPoint, 57));
    }

    @Override
    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return false;
    }
}
