package io.moatwel.util;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.crypto.eddsa.ed448.ph.Ed448phSchemeProvider;
import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class SharedKeyTest {

    private static final int TRIAL = 10;
    private HashAlgorithm algorithm = HashAlgorithm.KECCAK_512;
    private Edwards edwards = new Edwards(algorithm);

    @Test
    public void success_theSameSharedKey_many_times() {
        for (int i = 0; i < TRIAL; i++) {
            checkTheSameKey_on_Curve25519();
        }
    }

    @Test
    public void success_theSameSharedKey_on_curve448() {
        for (int i = 0; i < TRIAL; i++) {
            checkTheSameKey_on_Curve448();
        }
    }

    // Random check
    private void checkTheSameKey_on_Curve25519() {
        KeyPair keyPair1 = edwards.generateKeyPair();
        KeyPair keyPair2 = edwards.generateKeyPair();

        try {
            PublicKeyDelegate delegate = edwards.getSchemeProvider().getPublicKeyDelegate();
            Point point1 = EncodedPoint.from(keyPair1.getPublicKey().getRaw()).decode();
            Point point2 = EncodedPoint.from(keyPair2.getPublicKey().getRaw()).decode();

            // These are not mistakes.
            BigInteger integer1 = keyPair2.getPrivateKey().getScalarSeed(delegate);
            BigInteger integer2 = keyPair1.getPrivateKey().getScalarSeed(delegate);

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

    private void checkTheSameKey_on_Curve448() {
        Edwards edwards448 = new Edwards(new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256));

        KeyPair keyPair1 = edwards448.generateKeyPair();
        KeyPair keyPair2 = edwards448.generateKeyPair();

        try {
            PublicKeyDelegate delegate = edwards448.getSchemeProvider().getPublicKeyDelegate();
            Point point1 = EncodedPoint.from(keyPair1.getPublicKey().getRaw()).decode();
            Point point2 = EncodedPoint.from(keyPair2.getPublicKey().getRaw()).decode();

            BigInteger integer1 = keyPair2.getPrivateKey().getScalarSeed(delegate);
            BigInteger integer2 = keyPair1.getPrivateKey().getScalarSeed(delegate);

            Point result1 = point1.scalarMultiply(integer1);
            Point result2 = point2.scalarMultiply(integer2);

            byte[] publicKey1 = result1.encode().getValue();
            byte[] publicKey2 = result2.encode().getValue();

            assertThat(result1.getAffineX().getInteger(), is(result2.getAffineX().getInteger()));
            assertThat(result1.getAffineY().getInteger(), is(result2.getAffineY().getInteger()));

            assertThat(publicKey1.length, is(57));
            assertThat(publicKey2.length, is(57));

            assertThat(publicKey1, is(publicKey2));

        } catch (DecodeException e) {
            e.printStackTrace();
        }
    }
}
