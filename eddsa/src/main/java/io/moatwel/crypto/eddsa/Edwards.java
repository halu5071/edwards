package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.DsaSigner;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Curve;

public class Edwards {

    private Curve curve;
    private KeyGenerator generator;
    private DsaSigner signer;

    public Edwards() {
        this(new Builder());
    }

    Edwards(Builder builder) {
        this.curve = builder.curve;
        this.generator = builder.generator;
        this.signer = builder.signer;
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

    public DsaSigner getDsaSigner(KeyPair keyPair) {
        return signer;
    }

    public KeyGenerator getKeyGenerator() {
        return generator;
    }

    public static final class Builder {
        Curve curve;
        KeyGenerator generator;
        DsaSigner signer;

        public Builder() {
            this.curve = Ed25519Curve.getCurve();
            this.generator = new EdDsaKeyGenerator(curve);
            this.signer = new EdDsaSigner();
        }

        public Builder curve(Curve curve) {
            this.curve = curve;
            return this;
        }

        public Builder keyGenerator(KeyGenerator generator) {
            this.generator = generator;
            return this;
        }

        public Builder signer(DsaSigner signer) {
            this.signer = signer;
            return this;
        }

        public Edwards build() {
            return new Edwards(this);
        }
    }
}
