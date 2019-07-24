package io.moatwel.crypto.eddsa.ed448;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;

@State(Scope.Benchmark)
public class CoordinateEd448Benchmark {

    private Coordinate coordinateX = new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385"));
    private Coordinate coordinateY = new CoordinateEd448(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521"));

    @Benchmark
    public void Coordinate_Addition() {
        coordinateX.add(coordinateY);
    }

    @Benchmark
    public void Coordinate_Subtraction() {
        coordinateX.subtract(coordinateY);
    }

    @Benchmark
    public void Coordinate_multiplication() {
        coordinateX.multiply(coordinateY);
    }

    @Benchmark
    public void Coordinate_inverse() {
        coordinateX.inverse();
    }
}
