package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.ed25519.Ed25519CurveProvider;

/**
 * Base class for operations of EdDsa.
 *
 * @author halu5071 (Yasunori Horii) at 2018/6/9
 * @see CurveProvider
 * @see HashAlgorithm
 * @see EdDsaSigner
 */
public final class Edwards {

    private Curve curve;
    private KeyGenerator generator;
    private EdDsaSigner signer;

    public Edwards() {
        this(new Ed25519CurveProvider(HashAlgorithm.KECCAK_512));
    }

    public Edwards(HashAlgorithm algorithm) {
        this(new Ed25519CurveProvider(algorithm));
    }

    public Edwards(CurveProvider curveProvider) {
        if (curveProvider == null) {
            throw new NullPointerException("CurveProvider must not be null.");
        }
        this.curve = curveProvider.getCurve();
        this.generator = new EdDsaKeyGenerator(curveProvider);
        this.signer = curveProvider.getSigner();
    }

    public KeyPair generateKeyPair() {
        return generator.generateKeyPair();
    }

    public KeyPair generateKeyPair(PrivateKey privateKey) {
        return generator.generateKeyPair(privateKey);
    }

    public PublicKey derivePublicKey(PrivateKey privateKey) {
        return generator.derivePublicKey(privateKey);
    }

    public Signature sign(KeyPair keyPair, byte[] data) {
        return signer.sign(keyPair, data);
    }

    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return signer.verify(keyPair, data, signature);
    }

    public Curve getCurve() {
        return curve;
    }

    public EdDsaSigner getDsaSigner() {
        return signer;
    }

    public KeyGenerator getKeyGenerator() {
        return generator;
    }
}
