package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EncodedPointEd448Test {

    @Test
    public void success_DecodePoint_1() {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("81d3a88178237b46386f73ab08fdd87bc35ec0d5390fb2545f71e78d16cae5a7e0a9089bff7d11187312fff5cd3eab84cfbc2f4a8917e7e480"));

        Point point = encodedPoint.decode();

        assertThat(point.getY().getInteger(), is(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521")));
        assertThat(point.getX().getInteger(), is(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385")));
    }
}
