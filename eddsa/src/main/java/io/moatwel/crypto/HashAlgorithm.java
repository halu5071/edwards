package io.moatwel.crypto;

public enum HashAlgorithm {

    KECCAK_256("KECCAK-256"),

    KECCAK_512("KECCAK-512"),

    SHA3_256("SHA3-256"),

    SHA3_512("SHA3-512"),

    SHA_512("SHA-512");

    private String algorithm;

    HashAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getName() {
        return algorithm;
    }
}
