package io.moatwel.crypto.eddsa.nem;

import org.junit.Test;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class NemV2PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new NemV2PublicKeyDelegate();

    /** These test vectors were derived from nis on localhost:7890/account/generate **/
    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_1() {
        PrivateKey privateKey = PrivateKey.newInstance("a958255dbd7d642fa4fac6c775f2ee667340f5d005b1459f74c7d1c186ddc46a");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("ec830bacf66db8391a69817e174ac89cde7f2749bc62fd5f3f27a7c912fb3118"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_2() {
        PrivateKey privateKey = PrivateKey.newInstance("7aa75581e0b765a43a0e62a387710e3d3e58edb82da0758248ecb4ce7d9b846c");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("325346aa33cd778fd1c711e5e9f1591d145254095b42fdc58930204f6a57ff89"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_3() {
        PrivateKey privateKey = PrivateKey.newInstance("045fec62c7045296116daa3662b261e6b325c0ceced763ba9c5b9b370d468734");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("ab477c7e9ccc44877bcaae50c633934ade5802727ff3babdc1cc3f4ad1f213fc"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_4() {
        PrivateKey privateKey = PrivateKey.newInstance("6db8c7e3b27a8a4c93aa3deeb3d78cfb0fa6875e7bcd3f5839fa34d2baea4211");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("2c195df04f644ec962c294415c5de2e59cf59e1949f5d3f0344a5251eff761d8"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_5() {
        PrivateKey privateKey = PrivateKey.newInstance("d042535480ab81de641f5fb25ccb197d31adacfdae7d6f23c3c145b8bf9aa1fd");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("ec1ca16935c4efd928cbb61f822224709c24d216c64f93d5349f4f63307ae760"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_6() {
        PrivateKey privateKey = PrivateKey.newInstance("d21a5849ef0be8e59a6eca8009335486906289f93618d4c3dfbcb74f42373813");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("fdfd06266ce8fd51b9b09b4e18e8742ea0e071468205ed11b7048331a178b5e4"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_7() {
        PrivateKey privateKey = PrivateKey.newInstance("c46dfc93b28b8e1af50ea86a16e3b465188d0729d018714451f3aba87ab96774");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("fc278c719962d1bd60a1a63540b5b0643e54ffe8c6303647617f1770d447d079"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_8() {
        PrivateKey privateKey = PrivateKey.newInstance("a8db55354fa6fb4cb066444e2b11bf6bc2796e9b9c8dd568e558613b0073b30f");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("bc2a9778d249f81c5619d04b328a957334fe063a724c822d2af74f8868ed7cd9"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_9() {
        PrivateKey privateKey = PrivateKey.newInstance("c7a10487f0c2be5cf691b42864e13be95d172f67aa1c8e018932ce09f700d962");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("b87476a1dbf653018d04a688b70f0d152d469b6a76025a86ec6e776363e0a784"));
    }

    @Test
    public void success_GeneratePublicKeySeed_for_NEM_v1_10() {
        PrivateKey privateKey = PrivateKey.newInstance("766681155adef7ea3312f085e0db3ee5b82ef97ccb259e6a153203ab4058a9cc");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("8572aba7b580204112e746ddf8ebd798be391bba6958b3840e4a87786605d9de"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_DifferentPrivateKey() {
        byte[] seed = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56};
        PrivateKey privateKey = PrivateKey.newInstance(seed);

        delegate.generatePublicKeySeed(privateKey);
    }
}
