package io.moatwel.crypto;

import org.spongycastle.crypto.digests.SHAKEDigest;
import org.spongycastle.jcajce.provider.config.ConfigurableProvider;
import org.spongycastle.jcajce.provider.digest.BCMessageDigest;
import org.spongycastle.jcajce.provider.util.AlgorithmProvider;

public class Shake {

    private Shake() {
    }

    public static class DigestShake extends BCMessageDigest implements Cloneable {
        protected DigestShake(int length) {
            super(new SHAKEDigest(length));
        }
    }

    public static class Digest128 extends DigestShake {
        public Digest128() {
            super(128);
        }
    }

    public static class Digest256 extends DigestShake {
        public Digest256() {
            super(256);
        }
    }

    public static class Mappings extends AlgorithmProvider {
        private static final String PREFIX = Shake.class.getName();

        @Override
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("MessageDigest.SHAKE128", PREFIX + "$Digest128");
            provider.addAlgorithm("MessageDigest.SHAKE256", PREFIX + "$Digest256");
        }
    }
}
