package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class Ed25519PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new Ed25519PublicKeyDelegate();

    @Test
    public void success_GeneratePublicKeySeed() {
        PrivateKey privateKey = new PrivateKey(new byte[32]);

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(seed, is(new byte[]{70, 46, -23, 118, -119, 9, 22, -27, 79, -88, 37, -46, 107,
                -35, 2, 53, -11, -21, 91, 106, 20, 60, 25, -102, -80, -82, 94, -23, 50, -114, 8, -50}));
    }
}
