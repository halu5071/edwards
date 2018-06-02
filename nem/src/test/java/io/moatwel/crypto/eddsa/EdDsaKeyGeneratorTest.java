package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.CryptoEngine;
import io.moatwel.crypto.KeyAnalyzer;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(EdDsaKeyGenerator.class)
public class EdDsaKeyGeneratorTest {

    private CryptoEngine mockEngine;
    private PublicKey mockPublicKey;
    private PrivateKey mockPrivateKey;
    private KeyGenerator generator;
    private KeyAnalyzer mockAnalyzer;

    @Before
    public void setup() {
        mockEngine = mock(CryptoEngine.class);
        mockPublicKey = mock(PublicKey.class);
        mockPrivateKey = mock(PrivateKey.class);

        mockAnalyzer = mock(KeyAnalyzer.class);
        when(mockEngine.createKeyAnalyzer()).thenReturn(mockAnalyzer);
        when(mockEngine.createKeyGenerator()).thenReturn(generator);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(true);

        generator = new EdDsaKeyGenerator(Ed25519Curve.getEdCurve(), mockEngine);
    }

    @Test
    public void test() {
        System.out.println("Empty test");
    }
}
