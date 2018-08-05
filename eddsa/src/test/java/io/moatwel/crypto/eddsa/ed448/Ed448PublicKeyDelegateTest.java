package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.HexEncoder;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new Ed448PublicKeyDelegate(HashAlgorithm.SHA_512);

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_1() {
        PrivateKey privateKey = PrivateKeyEd448.fromHexString("d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_2() {
        PrivateKey privateKey = PrivateKeyEd448.fromHexString("2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_3() {
        PrivateKey privateKey = PrivateKeyEd448.fromHexString("872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400"));
    }
}
