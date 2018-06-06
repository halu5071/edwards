package io.moatwel.crypto.eddsa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.CryptoProvider;
import io.moatwel.crypto.KeyAnalyzer;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

@RunWith(PowerMockRunner.class)
public class EdCryptoProviderTest {

    @Test
    public void test() {
        CryptoProvider engine = new EdCryptoProvider(Ed25519Curve.getEdCurve());
        KeyGenerator generator = engine.createKeyGenerator();
        KeyAnalyzer analyzer = engine.createKeyAnalyzer();
    }
}
