package io.moatwel.crypto.eddsa.ed448;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.eddsa.Point;

@State(Scope.Benchmark)
public class PointEd448Benchmark {

    private Point point = new PointEd448(
            new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385")),
            new CoordinateEd448(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521")),
            new CoordinateEd448(BigInteger.ONE),
            new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385").multiply(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521"))).mod()
    );

    private BigInteger integer;

    public PointEd448Benchmark() {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[57];
        random.nextBytes(seed);
        integer = new BigInteger(seed);

    }

    @Benchmark
    public void Point_Addition() {
        point.add(point);
    }

    @Benchmark
    public void Point_Mulitiplication() {
        point.scalarMultiply(integer);
    }
}
