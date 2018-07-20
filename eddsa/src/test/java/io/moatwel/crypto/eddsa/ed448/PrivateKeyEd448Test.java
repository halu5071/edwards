package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

public class PrivateKeyEd448Test {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length() {
        PrivateKeyEd448.fromBytes(new byte[56]);
    }
}
