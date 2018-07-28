package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.HashProvider;
import io.moatwel.crypto.Hashes;

public class DefaultHashProvider implements HashProvider {

    private HashAlgorithm algorithm;

    public DefaultHashProvider(HashAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("DefaultHashProvider need non-null HashAlgorithm");
        }
        this.algorithm = algorithm;
    }

    @Override
    public byte[] hash(byte[]... inputs) {
        return Hashes.hash(algorithm, inputs);
    }
}
