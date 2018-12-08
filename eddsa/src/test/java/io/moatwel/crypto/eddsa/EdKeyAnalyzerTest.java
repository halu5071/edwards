package io.moatwel.crypto.eddsa;

import org.junit.Test;

import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed448.Curve448;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EdKeyAnalyzerTest {

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateKeyAnalyzer() {
        new EdKeyAnalyzer(null);
    }


    @Test
    public void success_IsKeyCompressed_Curve25519() {
        EdKeyAnalyzer analyzer = new EdKeyAnalyzer(Curve25519.getInstance());

        boolean isCompressed = analyzer.isKeyCompressed(PublicKey.fromHexString("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));

        assertThat(isCompressed, is(true));
    }

    @Test
    public void failure_IsKeyCompressed_Curve25519() {
        EdKeyAnalyzer analyzer = new EdKeyAnalyzer(Curve25519.getInstance());

        boolean isCompressed = analyzer.isKeyCompressed(PublicKey.fromHexString("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08"));

        assertThat(isCompressed, is(false));
    }

    @Test
    public void success_IsKeyCompressed_Curve448() {
        EdKeyAnalyzer analyzer = new EdKeyAnalyzer(Curve448.getInstance());

        boolean isCompressed = analyzer.isKeyCompressed(PublicKey.fromHexString(
                "5fd7449b59b461fd2ce787ec616ad46a" +
                "1da1342485a70e1f8a0ea75d80e96778" +
                "edf124769b46c7061bd6783df1e50f6c" +
                "d1fa1abeafe8256180"));

        assertThat(isCompressed, is(true));
    }

    @Test
    public void failure_IsKeyCompressed_Curve448() {
        EdKeyAnalyzer analyzer = new EdKeyAnalyzer(Curve448.getInstance());

        boolean isCompressed = analyzer.isKeyCompressed(PublicKey.fromHexString(
                "5fd7449b59b461fd2ce787ec616ad46a" +
                        "1da1342485a70e1f8a0ea75d80e96778" +
                        "edf124769b46c7061bd6783df1e50f6c" +
                        "d1fa1abeafe82561"));

        assertThat(isCompressed, is(false));
    }
}
