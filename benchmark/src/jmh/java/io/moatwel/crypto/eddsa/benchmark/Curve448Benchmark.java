package io.moatwel.crypto.eddsa.benchmark;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.ed448.Ed448SchemeProvider;

@State(Scope.Benchmark)
public class Curve448Benchmark {
    private Edwards edwards448 = new Edwards(new Ed448SchemeProvider(HashAlgorithm.SHAKE_256));
    private KeyPair pair448 = edwards448.generateKeyPair();
    private Signature signature448 = edwards448.sign(pair448, new byte[32]);

    @Benchmark
    public void generate_KeyPair() {
        edwards448.generateKeyPair();
    }

    @Benchmark
    public void sign() {
        edwards448.sign(pair448, new byte[32]);
    }

    @Benchmark
    public void verify() {
        edwards448.verify(pair448.getPublicKey(), new byte[32], signature448);
    }
}
