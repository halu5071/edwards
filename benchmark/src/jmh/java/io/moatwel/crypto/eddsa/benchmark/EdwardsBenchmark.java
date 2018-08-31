package io.moatwel.crypto.eddsa.benchmark;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Edwards;

@State(Scope.Benchmark)
public class EdwardsBenchmark {
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

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .resultFormat(ResultFormatType.JSON)
                .result("benchmark.json")
                .include(EdwardsBenchmark.class.getCanonicalName())
                .warmupIterations(5)
                .measurementIterations(5)
                .timeUnit(TimeUnit.MILLISECONDS)
                .forks(1)
                .mode(Mode.AverageTime)
                .build();
        new Runner(opt).run();
    }
}
