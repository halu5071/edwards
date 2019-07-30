package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.HexEncoder;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new Ed448PublicKeyDelegate(HashAlgorithm.SHAKE_256);

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_1() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "6c82a562cb808d10d632be89c8513ebf" +
                        "6c929f34ddfa8c9f63c9960ef6e348a3" +
                        "528c8a3fcc2f044e39a3fc5b94492f8f" +
                        "032e7549a20098f95b"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "5fd7449b59b461fd2ce787ec616ad46a" +
                        "1da1342485a70e1f8a0ea75d80e96778" +
                        "edf124769b46c7061bd6783df1e50f6c" +
                        "d1fa1abeafe8256180"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_2() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "43ba28f430cdff456ae531545f7ecd0a" +
                        "c834a55d9358c0372bfa0c6c6798c086" +
                        "6aea01eb00742802b8438ea4cb82169c" +
                        "235160627b4c3a9480"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_3() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "43ba28f430cdff456ae531545f7ecd0a" +
                        "c834a55d9358c0372bfa0c6c6798c086" +
                        "6aea01eb00742802b8438ea4cb82169c" +
                        "235160627b4c3a9480"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_4() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "cd23d24f714274e744343237b93290f5" +
                        "11f6425f98e64459ff203e8985083ffd" +
                        "f60500553abc0e05cd02184bdb89c4cc" +
                        "d67e187951267eb328"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "dcea9e78f35a1bf3499a831b10b86c90" +
                        "aac01cd84b67a0109b55a36e9328b1e3" +
                        "65fce161d71ce7131a543ea4cb5f7e9f" +
                        "1d8b00696447001400"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_5() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "258cdd4ada32ed9c9ff54e63756ae582" +
                        "fb8fab2ac721f2c8e676a72768513d93" +
                        "9f63dddb55609133f29adf86ec9929dc" +
                        "cb52c1c5fd2ff7e21b"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "3ba16da0c6f2cc1f30187740756f5e79" +
                        "8d6bc5fc015d7c63cc9510ee3fd44adc" +
                        "24d8e968b6e46e6f94d19b945361726b" +
                        "d75e149ef09817f580"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_6() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "7ef4e84544236752fbb56b8f31a23a10" +
                        "e42814f5f55ca037cdcc11c64c9a3b29" +
                        "49c1bb60700314611732a6c2fea98eeb" +
                        "c0266a11a93970100e"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "b3da079b0aa493a5772029f0467baebe" +
                        "e5a8112d9d3a22532361da294f7bb381" +
                        "5c5dc59e176b4d9f381ca0938e13c6c0" +
                        "7b174be65dfa578e80"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_7() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "d65df341ad13e008567688baedda8e9d" +
                        "cdc17dc024974ea5b4227b6530e339bf" +
                        "f21f99e68ca6968f3cca6dfe0fb9f4fa" +
                        "b4fa135d5542ea3f01"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "df9705f58edbab802c7f8363cfe5560a" +
                        "b1c6132c20a9f1dd163483a26f8ac53a" +
                        "39d6808bf4a1dfbd261b099bb03b3fb5" +
                        "0906cb28bd8a081f00"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_8() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "79756f014dcfe2079f5dd9e718be4171" +
                        "e2ef2486a08f25186f6bff43a9936b9b" +
                        "fe12402b08ae65798a3d81e22e9ec80e" +
                        "7690862ef3d4ed3a00"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHAKE_512_from_hex_string_9() {
        PrivateKey privateKey = PrivateKey.newInstance(HexEncoder.getBytes(
                "872d093780f5d3730df7c212664b37b8" +
                        "a0f24f56810daa8382cd4fa3f77634ec" +
                        "44dc54f1c2ed9bea86fafb7632d8be19" +
                        "9ea165f5ad55dd9ce8"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is(
                "a81b2e8a70a5ac94ffdbcc9badfc3feb" +
                        "0801f258578bb114ad44ece1ec0e799d" +
                        "a08effb81c5d685c0c56f64eecaef8cd" +
                        "f11cc38737838cf400"));
    }
}
