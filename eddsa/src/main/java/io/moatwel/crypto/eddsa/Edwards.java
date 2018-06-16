package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Signer;

public class Edwards {

    private Curve curve;
    private KeyGenerator generator;
    private EdDsaSigner signer;

    public Edwards() {
        this(Ed25519Curve.getCurve());
    }

    Edwards(Curve curve) {
        this.curve = curve;
        this.generator = new EdDsaKeyGenerator(curve);
        this.signer = curve.getSigner();
    }

    public KeyPair generateKeyPair() {
        return generator.generateKeyPair();
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

    public EdDsaSigner getDsaSigner(KeyPair keyPair) {
        return signer;
    }

    public KeyGenerator getKeyGenerator() {
        return generator;
    }
}
