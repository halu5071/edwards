package io.moatwel.crypto;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;
import io.moatwel.crypto.eddsa.EdKeyAnalyzer;
import io.moatwel.crypto.eddsa.EdKeyAnalyzerTestFactory;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed25519.Ed25519SchemeProvider;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({
        Edwards.class,
        PrivateKey.class,
        PublicKey.class,
        KeyGenerator.class,
        EdKeyAnalyzer.class,
        KeyPair.class})
public class KeyPairTest {

    private Edwards mockEdwards;
    private PrivateKey mockPrivateKey;
    private PublicKey mockPublicKey;
    private KeyGenerator mockGenerator;
    private EdKeyAnalyzer mockAnalyzer;
    private KeyPair mockTmpKeyPair;

    @Before
    public void setup() {
        mockEdwards = mock(Edwards.class);
        mockPrivateKey = mock(PrivateKey.class);
        mockPublicKey = mock(PublicKey.class);
        mockGenerator = mock(KeyGenerator.class);
        mockAnalyzer = mock(EdKeyAnalyzer.class);
        mockTmpKeyPair = mock(KeyPair.class);
    }

    @Test
    public void success_GenerateKeyPair_private_key_and_engine() {
        when(mockGenerator.derivePublicKey(mockPrivateKey)).thenReturn(mockPublicKey);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(true);

        KeyPair pair = new KeyPair(mockPrivateKey, mockGenerator, mockAnalyzer);

        assertThat(pair.getPublicKey(), is(mockPublicKey));
        assertThat(pair.getPrivateKey(), is(mockPrivateKey));
    }

    @Test
    public void success_GenerateKeyPair_random() {
        when(mockEdwards.getKeyGenerator()).thenReturn(mockGenerator);
        when(mockGenerator.generateKeyPair()).thenReturn(mockTmpKeyPair);
        when(mockTmpKeyPair.getPrivateKey()).thenReturn(mockPrivateKey);
        when(mockTmpKeyPair.getPublicKey()).thenReturn(mockPublicKey);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(true);

        KeyPair pair = mockEdwards.getKeyGenerator().generateKeyPair();

        assertThat(pair.getPrivateKey(), is(mockPrivateKey));
        assertThat(pair.getPublicKey(), is(mockPublicKey));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateKeyPair_public_key_not_compressed_1() {
        when(mockEdwards.getKeyGenerator()).thenReturn(mockGenerator);
        when(mockGenerator.derivePublicKey(mockPrivateKey)).thenReturn(mockPublicKey);
        when(mockAnalyzer.isKeyCompressed(mockPublicKey)).thenReturn(false);

        new KeyPair(mockPrivateKey, mockGenerator, mockAnalyzer);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateKeyPair_public_key_not_compressed_2() {
        PrivateKey privateKey = PrivateKey.newInstance(new byte[32]);
        EdKeyAnalyzer analyzer = EdKeyAnalyzerTestFactory.generate(Curve25519.getInstance());
        PublicKey publicKey = new PublicKey(new byte[31]);

        new KeyPair(privateKey, publicKey, analyzer);
    }

    @Test
    public void success_GenerateKeyPair_from_EdDsaKeyGenerator() {
        SchemeProvider schemeProvider = new Ed25519SchemeProvider(HashAlgorithm.KECCAK_512);
        EdDsaKeyGenerator generator = new EdDsaKeyGenerator(schemeProvider);
        PrivateKey privateKey = PrivateKey.newInstance(new byte[32]);
        EdKeyAnalyzer analyzer = EdKeyAnalyzerTestFactory.generate(Curve25519.getInstance());

        PublicKey checkKey = generator.derivePublicKey(privateKey);

        KeyPair keyPair = new KeyPair(privateKey, generator, analyzer);

        assertNotNull(keyPair);
        assertThat(keyPair.getPublicKey().getRaw(), is(checkKey.getRaw()));
    }
}
