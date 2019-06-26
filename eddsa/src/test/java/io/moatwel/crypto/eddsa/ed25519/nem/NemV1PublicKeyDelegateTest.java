package io.moatwel.crypto.eddsa.ed25519.nem;

import org.junit.Test;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class NemV1PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new NemV1PublicKeyDelegate();

    /** These test vectors were derived from nis on localhost:7890/account/generate **/
    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_1() {
        PrivateKey privateKey = PrivateKey.newInstance("a958255dbd7d642fa4fac6c775f2ee667340f5d005b1459f74c7d1c186ddc46a");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("c6281a16ec99d25421e539a21f4a542f4da4fcbab525ba14c1aa169898fd4794"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_2() {
        PrivateKey privateKey = PrivateKey.newInstance("7aa75581e0b765a43a0e62a387710e3d3e58edb82da0758248ecb4ce7d9b846c");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("9f067b408296fc1ea3369b9f0944fee263b8cf9a16a5fb5a025a76949b20fa6a"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_3() {
        PrivateKey privateKey = PrivateKey.newInstance("045fec62c7045296116daa3662b261e6b325c0ceced763ba9c5b9b370d468734");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("324c9c4fa40fd28d9570f0bbee76e33b3925689b6e3656efdabc798304515bf9"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_4() {
        PrivateKey privateKey = PrivateKey.newInstance("6db8c7e3b27a8a4c93aa3deeb3d78cfb0fa6875e7bcd3f5839fa34d2baea4211");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("355d9ccac7eeea7ba0ba7918c3d768e3f7bfc3d1f28c20f1fb69ac5a945e197c"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_5() {
        PrivateKey privateKey = PrivateKey.newInstance("d042535480ab81de641f5fb25ccb197d31adacfdae7d6f23c3c145b8bf9aa1fd");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("17c7084d76d641bfb6618a9853678dacf62be6a1da98b838088e630e776cd99c"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_6() {
        PrivateKey privateKey = PrivateKey.newInstance("d21a5849ef0be8e59a6eca8009335486906289f93618d4c3dfbcb74f42373813");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("1d830d870142d17b895ab692850db64c6580db9c45dea175187ec2cc7b442d34"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_7() {
        PrivateKey privateKey = PrivateKey.newInstance("c46dfc93b28b8e1af50ea86a16e3b465188d0729d018714451f3aba87ab96774");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("b2b72b351eb01ee988376ecc8defc1107d60023121b4ceb92fcc0f60fae54442"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_8() {
        PrivateKey privateKey = PrivateKey.newInstance("a8db55354fa6fb4cb066444e2b11bf6bc2796e9b9c8dd568e558613b0073b30f");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("52241a95d30ec523f79a4236a7bd748619ad472a54b1fdfe172ea1c0be2d0b06"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_9() {
        PrivateKey privateKey = PrivateKey.newInstance("c7a10487f0c2be5cf691b42864e13be95d172f67aa1c8e018932ce09f700d962");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("f5496c59ff336ae2d497140f0ad48306092beeda0d36c31c7373103956c90261"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_10() {
        PrivateKey privateKey = PrivateKey.newInstance("766681155adef7ea3312f085e0db3ee5b82ef97ccb259e6a153203ab4058a9cc");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("e2ec113bea44285e5f64f8a45f6ec71e9e2b806293f30e970fa5d77401447f35"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_DifferentPrivateKey() {
        byte[] seed = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56};
        PrivateKey privateKey = PrivateKey.newInstance(seed);

        delegate.generatePublicKeySeed(privateKey);
    }
}
