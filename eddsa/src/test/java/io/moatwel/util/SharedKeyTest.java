package io.moatwel.util;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class SharedKeyTest {

    private HashAlgorithm algorithm = HashAlgorithm.KECCAK_512;
    private Edwards edwards = new Edwards(algorithm);

    @Test
    public void success_theSameSharedKey_many_times() {
        for (int i = 0; i < 10; i++) {
            checkTheSameKey();
        }
    }

    // Random check
    private void checkTheSameKey() {
        KeyPair keyPair1 = edwards.generateKeyPair();
        KeyPair keyPair2 = edwards.generateKeyPair();

        try {
            Point point1 = EncodedPoint.from(keyPair1.getPublicKey().getRaw()).decode();
            Point point2 = EncodedPoint.from(keyPair2.getPublicKey().getRaw()).decode();

            // These are not mistakes.
            BigInteger integer1 = keyPair2.getPrivateKey().getScalarSeed(algorithm);
            BigInteger integer2 = keyPair1.getPrivateKey().getScalarSeed(algorithm);

            Point result1 = point1.scalarMultiply(integer1);
            Point result2 = point2.scalarMultiply(integer2);

            byte[] publicKey1 = result1.encode().getValue();
            byte[] publicKey2 = result2.encode().getValue();

            assertThat(result1.getAffineX().getInteger(), is(result2.getAffineX().getInteger()));
            assertThat(result1.getAffineY().getInteger(), is(result2.getAffineY().getInteger()));

            assertThat(publicKey1, is(publicKey2));
        } catch (DecodeException e) {
            e.printStackTrace();
        }

    }
}
