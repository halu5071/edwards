package io.moatwel.crypto;

public interface HashProvider {

    byte[] hash(byte[]... inputs);
}
