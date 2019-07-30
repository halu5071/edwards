package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;
import io.moatwel.crypto.eddsa.EdKeyAnalyzer;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.HexEncoder;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448VerifyTest {

    private SchemeProvider scheme = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);

    private KeyGenerator generator;
    private Edwards edwards;

    @Before
    public void setup() {
        generator = new EdDsaKeyGenerator(scheme);
        edwards = new Edwards(scheme);
    }

    @Test
    public void success_VerifyMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "6c82a562cb808d10d632be89c8513ebf" +
                        "6c929f34ddfa8c9f63c9960ef6e348a3" +
                        "528c8a3fcc2f044e39a3fc5b94492f8f" +
                        "032e7549a20098f95b");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "533a37f6bbe457251f023c0d88f976ae" +
                        "2dfb504a843e34d2074fd823d41a591f" +
                        "2b233f034f628281f2fd7a22ddd47d78" +
                        "28c59bd0a21bfd3980ff0d2028d4b18a" +
                        "9df63e006c5d1c2d345b925d8dc00b41" +
                        "04852db99ac5c7cdda8530a113a0f4db" +
                        "b61149f05a7363268c71d95808ff2e65" +
                        "2600"));

        boolean isValid = scheme.getSigner().verify(pair, new byte[0], null, signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_2() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "26b8f91727bd62897af15e41eb43c377" +
                        "efb9c610d48f2335cb0bd0087810f435" +
                        "2541b143c4b981b7e18f62de8ccdf633" +
                        "fc1bf037ab7cd779805e0dbcc0aae1cb" +
                        "cee1afb2e027df36bc04dcecbf154336" +
                        "c19f0af7e0a6472905e799f1953d2a0f" +
                        "f3348ab21aa4adafd1d234441cf807c0" +
                        "3a00"));

        boolean isValid = scheme.getSigner().verify(pair, new byte[]{3}, null, signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_3() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "d4f8f6131770dd46f40867d6fd5d5055" +
                        "de43541f8c5e35abbcd001b32a89f7d2" +
                        "151f7647f11d8ca2ae279fb842d60721" +
                        "7fce6e042f6815ea000c85741de5c8da" +
                        "1144a6a1aba7f96de42505d7a7298524" +
                        "fda538fccbbb754f578c1cad10d54d0d" +
                        "5428407e85dcbc98a49155c13764e66c" +
                        "3c00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("03"), HexEncoder.getBytes("666f6f"), signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_4() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "cd23d24f714274e744343237b93290f5" +
                        "11f6425f98e64459ff203e8985083ffd" +
                        "f60500553abc0e05cd02184bdb89c4cc" +
                        "d67e187951267eb328");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "1f0a8888ce25e8d458a21130879b840a" +
                        "9089d999aaba039eaf3e3afa090a09d3" +
                        "89dba82c4ff2ae8ac5cdfb7c55e94d5d" +
                        "961a29fe0109941e00b8dbdeea6d3b05" +
                        "1068df7254c0cdc129cbe62db2dc957d" +
                        "bb47b51fd3f213fb8698f064774250a5" +
                        "028961c9bf8ffd973fe5d5c206492b14" +
                        "0e00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("0c3e544074ec63b0265e0c"), null, signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_5() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "258cdd4ada32ed9c9ff54e63756ae582" +
                        "fb8fab2ac721f2c8e676a72768513d93" +
                        "9f63dddb55609133f29adf86ec9929dc" +
                        "cb52c1c5fd2ff7e21b");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "7eeeab7c4e50fb799b418ee5e3197ff6" +
                        "bf15d43a14c34389b59dd1a7b1b85b4a" +
                        "e90438aca634bea45e3a2695f1270f07" +
                        "fdcdf7c62b8efeaf00b45c2c96ba457e" +
                        "b1a8bf075a3db28e5c24f6b923ed4ad7" +
                        "47c3c9e03c7079efb87cb110d3a99861" +
                        "e72003cbae6d6b8b827e4e6c143064ff" +
                        "3c00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("64a65f3cdedcdd66811e2915"), new byte[0], signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_6() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "7ef4e84544236752fbb56b8f31a23a10" +
                        "e42814f5f55ca037cdcc11c64c9a3b29" +
                        "49c1bb60700314611732a6c2fea98eeb" +
                        "c0266a11a93970100e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "6a12066f55331b6c22acd5d5bfc5d712" +
                        "28fbda80ae8dec26bdd306743c5027cb" +
                        "4890810c162c027468675ecf645a8317" +
                        "6c0d7323a2ccde2d80efe5a1268e8aca" +
                        "1d6fbc194d3f77c44986eb4ab4177919" +
                        "ad8bec33eb47bbb5fc6e28196fd1caf5" +
                        "6b4e7e0ba5519234d047155ac727a105" +
                        "3100"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("64a65f3cdedcdd66811e2915e7"), new byte[0], signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_7() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "d65df341ad13e008567688baedda8e9d" +
                        "cdc17dc024974ea5b4227b6530e339bf" +
                        "f21f99e68ca6968f3cca6dfe0fb9f4fa" +
                        "b4fa135d5542ea3f01");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "554bc2480860b49eab8532d2a533b7d5" +
                        "78ef473eeb58c98bb2d0e1ce488a98b1" +
                        "8dfde9b9b90775e67f47d4a1c3482058" +
                        "efc9f40d2ca033a0801b63d45b3b722e" +
                        "f552bad3b4ccb667da350192b61c508c" +
                        "f7b6b5adadc2c8d9a446ef003fb05cba" +
                        "5f30e88e36ec2703b349ca229c267083" +
                        "3900"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes(
                "bd0f6a3747cd561bdddf4640a332461a" +
                        "4a30a12a434cd0bf40d766d9c6d458e5" +
                        "512204a30c17d1f50b5079631f64eb31" +
                        "12182da3005835461113718d1a5ef944"), null, signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void success_VerifyMessage_8() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880e8d4f1cfce2d7a" +
                        "61452d26da05896f0a50da66a239a8a1" +
                        "88b6d825b3305ad77b73fbac0836ecc6" +
                        "0987fd08527c1a8e80d5823e65cafe2a" +
                        "3d00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes(
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
                        "a69ccce38fabdf86f3bef6044819de11"), null, signature);

        assertThat(isValid, is(true));
    }

    @Test
    public void failure_VerifyMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "6c82a562cb808d10d632be89c8513ebf" +
                        "6c929f34ddfa8c9f63c9960ef6e348a3" +
                        "528c8a3fcc2f044e39a3fc5b94492f8f" +
                        "032e7549a20098f95b");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "533a37f6bbe457251f023c0d88f976ae" +
                        "2dfb504a843e34d2074fd823d41a591f" +
                        "2b233f034f628281f2fd7a22ddd47d78" +
                        "28c59bd0a21bfd3980ff0d2028d4b18a" +
                        "9df63e006c5d1c2d345b925d8dc00b41" +
                        "04852db99ac5c7cdda8530a113a0f4db" +
                        "b61149f05a7363268c71d95808ff2e65" +
                        "2600"));

        boolean isValid = scheme.getSigner().verify(pair, new byte[]{1}, null, signature);

        assertThat(isValid, is(false));
    }


    @Test
    public void failure_VerifyMessage_2() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "26b8f91727bd62897af15e41eb43c377" +
                        "efb9c610d48f2335cb0bd0087810f435" +
                        "2541b143c4b981b7e18f62de8ccdf633" +
                        "fc1bf037ab7cd779805e0dbcc0aae1cb" +
                        "cee1afb2e027df36bc04dcecbf154336" +
                        "c19f0af7e0a6472905e799f1953d2a0f" +
                        "f3348ab21aa4adafd1d234441cf807c0" +
                        "3a00"));

        boolean isValid = scheme.getSigner().verify(pair, new byte[]{4}, null, signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_3() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "d4f8f6131770dd46f40867d6fd5d5055" +
                        "de43541f8c5e35abbcd001b32a89f7d2" +
                        "151f7647f11d8ca2ae279fb842d60721" +
                        "7fce6e042f6815ea000c85741de5c8da" +
                        "1144a6a1aba7f96de42505d7a7298524" +
                        "fda538fccbbb754f578c1cad10d54d0d" +
                        "5428407e85dcbc98a49155c13764e66c" +
                        "3c00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("04"), HexEncoder.getBytes("666f6f"), signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_4() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "cd23d24f714274e744343237b93290f5" +
                        "11f6425f98e64459ff203e8985083ffd" +
                        "f60500553abc0e05cd02184bdb89c4cc" +
                        "d67e187951267eb328");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "1f0a8888ce25e8d458a21130879b840a" +
                        "9089d999aaba039eaf3e3afa090a09d3" +
                        "89dba82c4ff2ae8ac5cdfb7c55e94d5d" +
                        "961a29fe0109941e00b8dbdeea6d3b05" +
                        "1068df7254c0cdc129cbe62db2dc957d" +
                        "bb47b51fd3f213fb8698f064774250a5" +
                        "028961c9bf8ffd973fe5d5c206492b14" +
                        "0e00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("0d3e544074ec63b0265e0c"), null, signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_5() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "258cdd4ada32ed9c9ff54e63756ae582" +
                        "fb8fab2ac721f2c8e676a72768513d93" +
                        "9f63dddb55609133f29adf86ec9929dc" +
                        "cb52c1c5fd2ff7e21b");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "7eeeab7c4e50fb799b418ee5e3197ff6" +
                        "bf15d43a14c34389b59dd1a7b1b85b4a" +
                        "e90438aca634bea45e3a2695f1270f07" +
                        "fdcdf7c62b8efeaf00b45c2c96ba457e" +
                        "b1a8bf075a3db28e5c24f6b923ed4ad7" +
                        "47c3c9e03c7079efb87cb110d3a99861" +
                        "e72003cbae6d6b8b827e4e6c143064ff" +
                        "3c00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("64a65f3cdedcdd66811e2914"), new byte[0], signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_6() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "7ef4e84544236752fbb56b8f31a23a10" +
                        "e42814f5f55ca037cdcc11c64c9a3b29" +
                        "49c1bb60700314611732a6c2fea98eeb" +
                        "c0266a11a93970100e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "6a12066f55331b6c22acd5d5bfc5d712" +
                        "28fbda80ae8dec26bdd306743c5027cb" +
                        "4890810c162c027468675ecf645a8317" +
                        "6c0d7323a2ccde2d80efe5a1268e8aca" +
                        "1d6fbc194d3f77c44986eb4ab4177919" +
                        "ad8bec33eb47bbb5fc6e28196fd1caf5" +
                        "6b4e7e0ba5519234d047155ac727a105" +
                        "3100"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes("64a65f3cdedcdd66811e2915e4"), new byte[0], signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_7() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "d65df341ad13e008567688baedda8e9d" +
                        "cdc17dc024974ea5b4227b6530e339bf" +
                        "f21f99e68ca6968f3cca6dfe0fb9f4fa" +
                        "b4fa135d5542ea3f01");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "554bc2480860b49eab8532d2a533b7d5" +
                        "78ef473eeb58c98bb2d0e1ce488a98b1" +
                        "8dfde9b9b90775e67f47d4a1c3482058" +
                        "efc9f40d2ca033a0801b63d45b3b722e" +
                        "f552bad3b4ccb667da350192b61c508c" +
                        "f7b6b5adadc2c8d9a446ef003fb05cba" +
                        "5f30e88e36ec2703b349ca229c267083" +
                        "3900"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes(
                "bd0f6a3747cd561bdddf4640a332461a" +
                        "4a30a12a434cd0bf30d766d9c6d458e5" +
                        "512204a30c17d1f50b5079631f64eb31" +
                        "12182da3005835461113718d1a5ef944"), null, signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_8() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = new SignatureEd448(HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880e8d4f1cfce2d7a" +
                        "61452d26da05896f0a50da66a239a8a1" +
                        "88b6d825b3305ad77b73fbac0836ecc6" +
                        "0987fd08527c1a8e80d5823e65cafe2a" +
                        "3d00"));

        boolean isValid = scheme.getSigner().verify(pair, HexEncoder.getBytes(
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
                        "a69ccce38fabdf86f3bef6044819de12"), null, signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_9() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "d65df341ad13e008567688baedda8e9d" +
                        "cdc17dc024974ea5b4227b6530e339bf" +
                        "f21f99e68ca6968f3cca6dfe0fb9f4fa" +
                        "b4fa135d5542ea3f01");
        // make PublicKey to invoke DecodeException
        PublicKey publicKey = PublicKey.fromHexString(
                "000c43838ea49d80316e3d1a637e99dc" +
                        "7adc3fea0c5c7852798ba6d2385b0c66" +
                        "044462f1913cfb34abdc3fb6d1c1039c" +
                        "5e1b451827534ea300");

        EdKeyAnalyzer analyzer = edwards.getKeyGenerator().getKeyAnalyzer();

        KeyPair keyPair = new KeyPair(privateKey, publicKey, analyzer);

        // invoke DecodeException
        boolean isValid = edwards.verify(keyPair, "hoge".getBytes(), new byte[0], new SignatureEd448(new byte[57], new byte[57]));
        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_10() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        byte[] r = HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880");
        // This byte array will be an integer which is larger than prime L on Curve448.
        byte[] s = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 123};
        Signature signature = new SignatureEd448(r, s);

        boolean isValid = scheme.getSigner().verify(pair, "bob".getBytes(), null, signature);

        assertThat(isValid, is(false));
    }

    @Test
    public void failure_VerifyMessage_11() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        byte[] r = HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880");
        byte[] s = HexEncoder.getBytes(
                "feffffffffffffffffffffffffffffff" +
                        "ffffffffffffffffffffffffffffffff" +
                        "ffffffffffffffffffffffffffffffff" +
                        "ffffffffffffffffff");
        Signature signature = new SignatureEd448(r, s);

        scheme.getSigner().verify(pair, "bob".getBytes(), null, signature);
    }

    @Test
    public void failure_VerifyMessage_12() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        byte[] r = HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880");
        byte[] s = HexEncoder.getBytes(
                "f44458ab92c27823558fc58d72c26c2" +
                        "19036d6ae49db4ec4e923ca7cffffff" +
                        "fffffffffffffffffffffffffffffff" +
                        "fffffffffffffffff3f00");
        Signature signature = new SignatureEd448(r, s);

        boolean isVerified = scheme.getSigner().verify(pair, "bob".getBytes(), null, signature);
        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifyMessage_13() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        byte[] r = HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880");
        byte[] s = HexEncoder.getBytes(
                "f34458ab92c27823558fc58d72c26c2" +
                        "19036d6ae49db4ec4e923ca7cffffff" +
                        "fffffffffffffffffffffffffffffff" +
                        "fffffffffffffffff3f00");
        Signature signature = new SignatureEd448(r, s);

        boolean isVerified = scheme.getSigner().verify(pair, "bob".getBytes(), null, signature);
        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifyMessage_14() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        byte[] r = HexEncoder.getBytes(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880");
        byte[] s = HexEncoder.getBytes(
                "f24458ab92c27823558fc58d72c26c2" +
                        "19036d6ae49db4ec4e923ca7cffffff" +
                        "fffffffffffffffffffffffffffffff" +
                        "fffffffffffffffff3f00");
        Signature signature = new SignatureEd448(r, s);

        boolean isVerified = scheme.getSigner().verify(pair, "bob".getBytes(), null, signature);
        assertThat(isVerified, is(false));
    }

    @Test(expected = IllegalStateException.class)
    public void failure_TooLongContext() {
        byte[] context = new byte[256];
        KeyPair pair = generator.generateKeyPair();
        Signature signature = scheme.getSigner().sign(pair, "hoge".getBytes(), null);
        scheme.getSigner().verify(pair, "hoge".getBytes(), context, signature);
    }
}
