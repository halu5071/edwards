package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.Signature;

public interface SignerDelegate {

    Signature sign(KeyPair keyPair, byte[] data);

    boolean verify(KeyPair keyPair, byte[] data, Signature signature);
}
