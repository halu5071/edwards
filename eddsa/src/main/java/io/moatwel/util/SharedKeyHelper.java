package io.moatwel.util;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.HashDelegate;
import io.moatwel.crypto.eddsa.Point;

import java.math.BigInteger;

public class SharedKeyHelper {

    public static byte[] generateSharedKeySeed(
            PublicKey publicKey,
            PrivateKey privateKey,
            HashDelegate hashDelegate) throws DecodeException {
        Point point = EncodedPoint.from(publicKey.getRaw()).decode();
        BigInteger scalarSeed = privateKey.getScalarSeed(hashDelegate);

        Point result = point.scalarMultiply(scalarSeed);

        return result.encode().getValue();
    }
}
