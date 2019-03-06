package io.moatwel.crypto.eddsa.benchmark;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Edwards;

@State(Scope.Benchmark)
public class Curve25519Benchmark {
    private Edwards edwards = new Edwards();
    private KeyPair pair = edwards.generateKeyPair();
    private Signature signature = edwards.sign(pair, new byte[32]);

    @Benchmark
    public void generate_KeyPair() {
        edwards.generateKeyPair();
    }

    @Benchmark
    public void sign() {
        edwards.sign(pair, new byte[32]);
    }

    @Benchmark
    public void verify() {
        edwards.verify(pair, new byte[32], signature);
    }
}
