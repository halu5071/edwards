package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.ed25519.Ed25519SchemeProvider;

/**
 * Base class for operations of EdDsa.
 *
 * This class is a thread-safe. See newInstance() methods.
 *
 * @author halu5071 (Yasunori Horii)
 * @see SchemeProvider
 * @see HashAlgorithm
 * @see EdDsaSigner
 */
public final class Edwards {

    private Curve curve;
    private KeyGenerator generator;
    private EdDsaSigner signer;

    public static Edwards newInstance(final HashAlgorithm algorithm) {
        ThreadLocal<Edwards> instance = new ThreadLocal<Edwards>() {
            @Override
            protected Edwards initialValue() {
                return new Edwards(algorithm);
            }
        };
        return instance.get();
    }

    public static Edwards newInstance(final SchemeProvider schemeProvider) {
        ThreadLocal<Edwards> instance = new ThreadLocal<Edwards>() {
            @Override
            protected Edwards initialValue() {
                return new Edwards(schemeProvider);
            }
        };
        return instance.get();
    }

    public static Edwards newInstance() {
        ThreadLocal<Edwards> instance = new ThreadLocal<Edwards>() {
            @Override
            protected Edwards initialValue() {
                return new Edwards();
            }
        };
        return instance.get();
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
        return signer.sign(keyPair, data, null);
    }

    public Signature sign(KeyPair keyPair, byte[] data, byte[] context) {
        return signer.sign(keyPair, data, context);
    }

    public boolean verify(KeyPair keyPair, byte[] data, Signature signature) {
        return signer.verify(keyPair, data, null, signature);
    }

    public boolean verify(KeyPair keyPair, byte[] data, byte[] context, Signature signature) {
        return signer.verify(keyPair, data, context, signature);
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

    private Edwards() {
        this(new Ed25519SchemeProvider(HashAlgorithm.KECCAK_512));
    }

    private Edwards(HashAlgorithm algorithm) {
        this(new Ed25519SchemeProvider(algorithm));
    }

    private Edwards(SchemeProvider schemeProvider) {
        if (schemeProvider == null) {
            throw new IllegalArgumentException("SchemeProvider must not be null.");
        }
        this.curve = schemeProvider.getCurve();
        this.generator = new EdDsaKeyGenerator(schemeProvider);
        this.signer = schemeProvider.getSigner();
    }
}
