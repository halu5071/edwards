package io.moatwel.crypto.eddsa;

/**
 * Factory class for testing
 */
public class EdKeyAnalyzerTestFactory {

    public static EdKeyAnalyzer generate(Curve curve) {
        return new EdKeyAnalyzer(curve);
    }
}
