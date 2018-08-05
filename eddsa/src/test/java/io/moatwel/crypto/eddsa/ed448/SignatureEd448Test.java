package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.*;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.EdKeyAnalyzer;
import io.moatwel.util.HexEncoder;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class SignatureEd448Test {

    private Curve curve = Ed448Curve.getCurve();
    private EdKeyAnalyzer analyzer = new EdKeyAnalyzer(curve);
    private EdDsaSigner signer = new Ed448Signer();

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_1() {
        byte[] r = new byte[56];
        byte[] s = new byte[57];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_2() {
        byte[] r = new byte[57];
        byte[] s = new byte[58];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_3() {
        byte[] r = new byte[57];
        byte[] s = new byte[56];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_4() {
        byte[] r = new byte[56];
        byte[] s = new byte[57];

        new SignatureEd448(r, s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateSignature_wrong_byte_arrays_5() {
        byte[] r = new byte[58];
        byte[] s = new byte[56];

        new SignatureEd448(r, s);
    }

    @Test
    public void success_JoinSignature() {
        byte[] input1 = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78, 37, 13, -19, 20, 21, -82, 3, 43, 62, 73, -2, -15, 23, 53, 63, 31, 91, 94, -5, 26, 57, 18, 91, 110, 78};
        byte[] input2 = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 51, 53, 79, 10, -31, 23, -52, 1, -4, 24, 38, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};

        Signature signature = new SignatureEd448(input1, input2);

        assertNotNull(signature);

        byte[] result = signature.getSignature();

        assertThat(result.length, is(114));
        assertThat(result, is(new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78, 37, 13, -19, 20, 21, -82, 3, 43, 62, 73, -2, -15, 23, 53, 63, 31, 91, 94, -5, 26, 57, 18, 91, 110, 78,
                -82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 51, 53, 79, 10, -31, 23, -52, 1, -4, 24, 38, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38}));
    }

    @Test
    public void success_SignMessage_1() {
        PrivateKey privateKey = PrivateKeyEd448.fromHexString("d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01");
        PublicKey publicKey = PublicKey.fromHexString("df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00");
        KeyPair pair = new KeyPair(privateKey, publicKey, analyzer);

        Signature signature = signer.sign(pair, HexEncoder.getBytes("bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944"));

        assertThat(signature.getSignature(), is(HexEncoder.getBytes("554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900")));
    }

    @Test
    public void success_SignMessage_2() {
        PrivateKey privateKey = PrivateKeyEd448.fromHexString("2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5");
        PublicKey publicKey = PublicKey.fromHexString("79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00");
        KeyPair pair = new KeyPair(privateKey, publicKey, analyzer);

        Signature signature = signer.sign(pair, HexEncoder.getBytes(
                "15777532b0bdd0d1389f636c5f6b9ba7" +
                        "34c90af572877e2d272dd078aa1e567c" +
                        "fa80e12928bb542330e8409f31745041" +
                        "07ecd5efac61ae7504dabe2a602ede89" +
                        "e5cca6257a7c77e27a702b3ae39fc769" +
                        "fc54f2395ae6a1178cab4738e543072f" +
                        "c1c177fe71e92e25bf03e4ecb72f47b6" +
                        "4d0465aaea4c7fad372536c8ba516a60" +
                        "39c3c2a39f0e4d832be432dfa9a706a6" +
                        "e5c7e19f397964ca4258002f7c0541b5" +
                        "90316dbc5622b6b2a6fe7a4abffd9610" +
                        "5eca76ea7b98816af0748c10df048ce0" +
                        "12d901015a51f189f3888145c03650aa" +
                        "23ce894c3bd889e030d565071c59f409" +
                        "a9981b51878fd6fc110624dcbcde0bf7" +
                        "a69ccce38fabdf86f3bef6044819de11"));

        assertThat(signature.getSignature(), is(HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880e8d4f1cfce2d7a" +
                        "61452d26da05896f0a50da66a239a8a1" +
                        "88b6d825b3305ad77b73fbac0836ecc6" +
                        "0987fd08527c1a8e80d5823e65cafe2a" +
                        "3d00")));
    }

    @Test
    public void success_SignMessage_3() {
        PrivateKey privateKey = PrivateKeyEd448.fromHexString("872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8");
        PublicKey publicKey = PublicKey.fromHexString("a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400");
        KeyPair pair = new KeyPair(privateKey, publicKey, analyzer);

        Signature signature = signer.sign(pair, HexEncoder.getBytes(
                "6ddf802e1aae4986935f7f981ba3f035" +
                        "1d6273c0a0c22c9c0e8339168e675412" +
                        "a3debfaf435ed651558007db4384b650" +
                        "fcc07e3b586a27a4f7a00ac8a6fec2cd" +
                        "86ae4bf1570c41e6a40c931db27b2faa" +
                        "15a8cedd52cff7362c4e6e23daec0fbc" +
                        "3a79b6806e316efcc7b68119bf46bc76" +
                        "a26067a53f296dafdbdc11c77f7777e9" +
                        "72660cf4b6a9b369a6665f02e0cc9b6e" +
                        "dfad136b4fabe723d2813db3136cfde9" +
                        "b6d044322fee2947952e031b73ab5c60" +
                        "3349b307bdc27bc6cb8b8bbd7bd32321" +
                        "9b8033a581b59eadebb09b3c4f3d2277" +
                        "d4f0343624acc817804728b25ab79717" +
                        "2b4c5c21a22f9c7839d64300232eb66e" +
                        "53f31c723fa37fe387c7d3e50bdf9813" +
                        "a30e5bb12cf4cd930c40cfb4e1fc6225" +
                        "92a49588794494d56d24ea4b40c89fc0" +
                        "596cc9ebb961c8cb10adde976a5d602b" +
                        "1c3f85b9b9a001ed3c6a4d3b1437f520" +
                        "96cd1956d042a597d561a596ecd3d173" +
                        "5a8d570ea0ec27225a2c4aaff26306d1" +
                        "526c1af3ca6d9cf5a2c98f47e1c46db9" +
                        "a33234cfd4d81f2c98538a09ebe76998" +
                        "d0d8fd25997c7d255c6d66ece6fa56f1" +
                        "1144950f027795e653008f4bd7ca2dee" +
                        "85d8e90f3dc315130ce2a00375a318c7" +
                        "c3d97be2c8ce5b6db41a6254ff264fa6" +
                        "155baee3b0773c0f497c573f19bb4f42" +
                        "40281f0b1f4f7be857a4e59d416c06b4" +
                        "c50fa09e1810ddc6b1467baeac5a3668" +
                        "d11b6ecaa901440016f389f80acc4db9" +
                        "77025e7f5924388c7e340a732e554440" +
                        "e76570f8dd71b7d640b3450d1fd5f041" +
                        "0a18f9a3494f707c717b79b4bf75c984" +
                        "00b096b21653b5d217cf3565c9597456" +
                        "f70703497a078763829bc01bb1cbc8fa" +
                        "04eadc9a6e3f6699587a9e75c94e5bab" +
                        "0036e0b2e711392cff0047d0d6b05bd2" +
                        "a588bc109718954259f1d86678a579a3" +
                        "120f19cfb2963f177aeb70f2d4844826" +
                        "262e51b80271272068ef5b3856fa8535" +
                        "aa2a88b2d41f2a0e2fda7624c2850272" +
                        "ac4a2f561f8f2f7a318bfd5caf969614" +
                        "9e4ac824ad3460538fdc25421beec2cc" +
                        "6818162d06bbed0c40a387192349db67" +
                        "a118bada6cd5ab0140ee273204f628aa" +
                        "d1c135f770279a651e24d8c14d75a605" +
                        "9d76b96a6fd857def5e0b354b27ab937" +
                        "a5815d16b5fae407ff18222c6d1ed263" +
                        "be68c95f32d908bd895cd76207ae7264" +
                        "87567f9a67dad79abec316f683b17f2d" +
                        "02bf07e0ac8b5bc6162cf94697b3c27c" +
                        "d1fea49b27f23ba2901871962506520c" +
                        "392da8b6ad0d99f7013fbc06c2c17a56" +
                        "9500c8a7696481c1cd33e9b14e40b82e" +
                        "79a5f5db82571ba97bae3ad3e0479515" +
                        "bb0e2b0f3bfcd1fd33034efc6245eddd" +
                        "7ee2086ddae2600d8ca73e214e8c2b0b" +
                        "db2b047c6a464a562ed77b73d2d841c4" +
                        "b34973551257713b753632efba348169" +
                        "abc90a68f42611a40126d7cb21b58695" +
                        "568186f7e569d2ff0f9e745d0487dd2e" +
                        "b997cafc5abf9dd102e62ff66cba87"));

        assertThat(signature.getSignature(), is(HexEncoder.getBytes(
                "e301345a41a39a4d72fff8df69c98075" +
                        "a0cc082b802fc9b2b6bc503f926b65bd" +
                        "df7f4c8f1cb49f6396afc8a70abe6d8a" +
                        "ef0db478d4c6b2970076c6a0484fe76d" +
                        "76b3a97625d79f1ce240e7c576750d29" +
                        "5528286f719b413de9ada3e8eb78ed57" +
                        "3603ce30d8bb761785dc30dbc320869e" +
                        "1a00")));
    }
}
