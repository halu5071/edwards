package io.moatwel.crypto.eddsa.ed25519;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;

@State(Scope.Benchmark)
public class CoordinateEd25519Benchmark {

    private Coordinate coordinateX = new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831"));
    private Coordinate coordinateY = new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982"));

    @Benchmark
    public void Coordinate_Addition() {
        coordinateX.add(coordinateY);
    }

    @Benchmark
    public void Coordiante_Subtraction() {
        coordinateX.subtract(coordinateY);
    }

    @Benchmark
    public void Coordinate_multiplication() {
        coordinateX.multiply(coordinateY);
    }

    @Benchmark
    public void Coodinate_inverse() {
        coordinateX.inverse();
    }
}
