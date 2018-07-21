package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;

@RunWith(PowerMockRunner.class)
public class EdwardsTest {

    private Edwards edwards;

    @Before
    public void setup() {
        edwards = new Edwards();
    }

    @Test
    public void test() {
        System.out.println("Empty test: EdwardsTest");
    }
}
