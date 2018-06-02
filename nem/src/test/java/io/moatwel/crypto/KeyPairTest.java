package io.moatwel.crypto;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.powermock.api.mockito.PowerMockito.*;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(KeyPair.class)
public class KeyPairTest {

    private CryptoEngine mockEngine;
    private PrivateKey mockPrivateKey;
    private PublicKey mockPublicKey;
    private KeyGenerator mockGenerator;
    private KeyAnalyzer mockAnalyzer;
    private KeyPair mockTmpKeyPair;

    @Before
    public void setup() {
        mockEngine = mock(CryptoEngine.class);
        mockPrivateKey = mock(PrivateKey.class);
        mockPublicKey = mock(PublicKey.class);
        mockGenerator = mock(KeyGenerator.class);
        mockAnalyzer = mock(KeyAnalyzer.class);
        mockTmpKeyPair = mock(KeyPair.class);
    }

    @Test
    public void success_GenerateKeyPair_private_key_and_engine() {
        when(mockEngine.createKeyGenerator()).thenReturn(mockGenerator);
        when(mockGenerator.derivePublicKey(mockPrivateKey)).thenReturn(mockPublicKey);
        when(mockEngine.createKeyAnalyzer()).thenReturn(mockAnalyzer);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(true);

        KeyPair pair = new KeyPair(mockPrivateKey, mockEngine);

        assertThat(pair.getPublicKey(), is(mockPublicKey));
        assertThat(pair.getPrivateKey(), is(mockPrivateKey));
    }

    @Test
    public void success_GenerateKeyPair_random() {
        when(mockEngine.createKeyGenerator()).thenReturn(mockGenerator);
        when(mockGenerator.generateKeyPair()).thenReturn(mockTmpKeyPair);
        when(mockTmpKeyPair.getPrivateKey()).thenReturn(mockPrivateKey);
        when(mockTmpKeyPair.getPublicKey()).thenReturn(mockPublicKey);
        when(mockEngine.createKeyAnalyzer()).thenReturn(mockAnalyzer);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(true);

        KeyPair pair = KeyPair.random(mockEngine);

        assertThat(pair.getPrivateKey(), is(mockPrivateKey));
        assertThat(pair.getPublicKey(), is(mockPublicKey));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fail_GenerateKeyPair_public_key_not_compressed() {
        when(mockEngine.createKeyGenerator()).thenReturn(mockGenerator);
        when(mockGenerator.derivePublicKey(mockPrivateKey)).thenReturn(mockPublicKey);
        when(mockEngine.createKeyAnalyzer()).thenReturn(mockAnalyzer);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(false);

        new KeyPair(mockPrivateKey, mockEngine);
    }
}
