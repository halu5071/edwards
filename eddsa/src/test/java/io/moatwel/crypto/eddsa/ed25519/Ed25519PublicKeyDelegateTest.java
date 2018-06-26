package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class Ed25519PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new Ed25519PublicKeyDelegate(HashAlgorithm.KECCAK_512);

    @Test
    public void success_GeneratePublicKeySeed() {
        PrivateKey privateKey = new PrivateKey(new byte[32]);

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        byte[] value = new byte[]{70, 46, -23, 118, -119, 9, 22, -27, 79, -88, 37, -46, 107,
                -35, 2, 53, -11, -21, 91, 106, 20, 60, 25, -102, -80, -82, 94, -23, 50, -114, 8, -50};

        assertThat(seed, is(value));
        assertThat(HexEncoder.getString(value), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
        assertThat(HexEncoder.getString(seed), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
    }
}
