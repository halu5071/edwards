package io.moatwel.crypto.eddsa.ed25519;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Point;

@State(Scope.Benchmark)
public class PointEd25519Benchmark {

    private Point point = PointEd25519.fromAffine(
            new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
            new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982"))
    );

    @Benchmark
    public void Point_Addition() {
        point.add(point);
    }

    @Benchmark
    public void Point_Multiplication() {
        point.scalarMultiply(new BigInteger("50459379271018302582465998844449622265826330103819895252966304478993432089656"));
    }
}
