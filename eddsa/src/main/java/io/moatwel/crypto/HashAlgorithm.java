package io.moatwel.crypto;

public enum HashAlgorithm {

    KECCAK_256("KECCAK-256", 256),

    KECCAK_512("KECCAK-512", 512),

    SHA3_256("SHA3-256", 256),

    SHA3_512("SHA3-512", 512),

    SHA_512("SHA-512", 512),

    SHAKE_128("SHAKE-128", 128),

    SHAKE_256("SHAKE-256", 256);

    private String algorithm;
    private int defaultByteLength;

    HashAlgorithm(String algorithm, int defaultByteLength) {
        this.algorithm = algorithm;
        this.defaultByteLength = defaultByteLength;
    }

    public String getName() {
        return algorithm;
    }

    public int getDefaultByteLength() {
        return defaultByteLength;
    }
}
