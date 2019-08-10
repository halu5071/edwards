package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.PrivateKey;

public interface HashDelegate {

    byte[] hashPrivateKey(PrivateKey privateKey);
}
