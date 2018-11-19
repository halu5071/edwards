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
    private int defaultBitLength;

    HashAlgorithm(String algorithm, int defaultBitLength) {
        this.algorithm = algorithm;
        this.defaultBitLength = defaultBitLength;
    }

    public String getName() {
        return algorithm;
    }

    public int getDefaultBitLength() {
        return defaultBitLength;
    }
}
