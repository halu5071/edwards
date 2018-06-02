package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

public class GenerateKeyTest {
    public static void main(String[] args) {
        EdDsaKeyGenerator generator = new EdDsaKeyGenerator(Ed25519Curve.getEdCurve(), new EdCryptoEngine());
    }
}
