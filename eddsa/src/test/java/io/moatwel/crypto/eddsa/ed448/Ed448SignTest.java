package io.moatwel.crypto.eddsa.ed448;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;
import io.moatwel.crypto.eddsa.SchemeProvider;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448SignTest {

    private SchemeProvider scheme = new Ed448SchemeProvider(HashAlgorithm.SHAKE_256);

    private KeyGenerator generator;

    @Before
    public void setup() {
        generator = new EdDsaKeyGenerator(scheme);
    }

    @Test
    public void success_SignMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "6c82a562cb808d10d632be89c8513ebf" +
                        "6c929f34ddfa8c9f63c9960ef6e348a3" +
                        "528c8a3fcc2f044e39a3fc5b94492f8f" +
                        "032e7549a20098f95b");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, new byte[0], new byte[0]);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "533a37f6bbe457251f023c0d88f976ae" +
                        "2dfb504a843e34d2074fd823d41a591f" +
                        "2b233f034f628281f2fd7a22ddd47d78" +
                        "28c59bd0a21bfd3980ff0d2028d4b18a" +
                        "9df63e006c5d1c2d345b925d8dc00b41" +
                        "04852db99ac5c7cdda8530a113a0f4db" +
                        "b61149f05a7363268c71d95808ff2e65" +
                        "2600"));
        assertThat(HexEncoder.getString(byteR), is("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"));
        assertThat(HexEncoder.getString(byteS), is("ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"));
    }

    @Test
    public void success_SignMessage_2() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, new byte[]{3}, new byte[0]);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "26b8f91727bd62897af15e41eb43c377" +
                        "efb9c610d48f2335cb0bd0087810f435" +
                        "2541b143c4b981b7e18f62de8ccdf633" +
                        "fc1bf037ab7cd779805e0dbcc0aae1cb" +
                        "cee1afb2e027df36bc04dcecbf154336" +
                        "c19f0af7e0a6472905e799f1953d2a0f" +
                        "f3348ab21aa4adafd1d234441cf807c0" +
                        "3a00"));
        assertThat(HexEncoder.getString(byteR), is("26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd77980"));
        assertThat(HexEncoder.getString(byteS), is("5e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"));
    }

    @Test
    public void success_SignMessage_3() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, HexEncoder.getBytes("03"), HexEncoder.getBytes("666f6f"));

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "d4f8f6131770dd46f40867d6fd5d5055" +
                        "de43541f8c5e35abbcd001b32a89f7d2" +
                        "151f7647f11d8ca2ae279fb842d60721" +
                        "7fce6e042f6815ea000c85741de5c8da" +
                        "1144a6a1aba7f96de42505d7a7298524" +
                        "fda538fccbbb754f578c1cad10d54d0d" +
                        "5428407e85dcbc98a49155c13764e66c" +
                        "3c00"));
        assertThat(HexEncoder.getString(byteR), is("d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea00"));
        assertThat(HexEncoder.getString(byteS), is("0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00"));
    }

    @Test
    public void success_SignMessage_4() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "cd23d24f714274e744343237b93290f5" +
                        "11f6425f98e64459ff203e8985083ffd" +
                        "f60500553abc0e05cd02184bdb89c4cc" +
                        "d67e187951267eb328");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, HexEncoder.getBytes("0c3e544074ec63b0265e0c"), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "1f0a8888ce25e8d458a21130879b840a" +
                        "9089d999aaba039eaf3e3afa090a09d3" +
                        "89dba82c4ff2ae8ac5cdfb7c55e94d5d" +
                        "961a29fe0109941e00b8dbdeea6d3b05" +
                        "1068df7254c0cdc129cbe62db2dc957d" +
                        "bb47b51fd3f213fb8698f064774250a5" +
                        "028961c9bf8ffd973fe5d5c206492b14" +
                        "0e00"));
        assertThat(HexEncoder.getString(byteR), is("1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00"));
        assertThat(HexEncoder.getString(byteS), is("b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00"));
    }

    @Test
    public void success_SignMessage_5() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "258cdd4ada32ed9c9ff54e63756ae582" +
                        "fb8fab2ac721f2c8e676a72768513d93" +
                        "9f63dddb55609133f29adf86ec9929dc" +
                        "cb52c1c5fd2ff7e21b");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, HexEncoder.getBytes("64a65f3cdedcdd66811e2915"), new byte[0]);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "7eeeab7c4e50fb799b418ee5e3197ff6" +
                        "bf15d43a14c34389b59dd1a7b1b85b4a" +
                        "e90438aca634bea45e3a2695f1270f07" +
                        "fdcdf7c62b8efeaf00b45c2c96ba457e" +
                        "b1a8bf075a3db28e5c24f6b923ed4ad7" +
                        "47c3c9e03c7079efb87cb110d3a99861" +
                        "e72003cbae6d6b8b827e4e6c143064ff" +
                        "3c00"));
        assertThat(HexEncoder.getString(byteR), is("7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00"));
        assertThat(HexEncoder.getString(byteS), is("b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00"));
    }

    @Test
    public void success_SignMessage_6() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "7ef4e84544236752fbb56b8f31a23a10" +
                        "e42814f5f55ca037cdcc11c64c9a3b29" +
                        "49c1bb60700314611732a6c2fea98eeb" +
                        "c0266a11a93970100e");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, HexEncoder.getBytes("64a65f3cdedcdd66811e2915e7"), new byte[0]);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "6a12066f55331b6c22acd5d5bfc5d712" +
                        "28fbda80ae8dec26bdd306743c5027cb" +
                        "4890810c162c027468675ecf645a8317" +
                        "6c0d7323a2ccde2d80efe5a1268e8aca" +
                        "1d6fbc194d3f77c44986eb4ab4177919" +
                        "ad8bec33eb47bbb5fc6e28196fd1caf5" +
                        "6b4e7e0ba5519234d047155ac727a105" +
                        "3100"));
        assertThat(HexEncoder.getString(byteR), is("6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80"));
        assertThat(HexEncoder.getString(byteS), is("efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100"));
    }

    @Test
    public void success_SignMessage_7() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "d65df341ad13e008567688baedda8e9d" +
                        "cdc17dc024974ea5b4227b6530e339bf" +
                        "f21f99e68ca6968f3cca6dfe0fb9f4fa" +
                        "b4fa135d5542ea3f01");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, HexEncoder.getBytes(
                "bd0f6a3747cd561bdddf4640a332461a" +
                        "4a30a12a434cd0bf40d766d9c6d458e5" +
                        "512204a30c17d1f50b5079631f64eb31" +
                        "12182da3005835461113718d1a5ef944"), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "554bc2480860b49eab8532d2a533b7d5" +
                        "78ef473eeb58c98bb2d0e1ce488a98b1" +
                        "8dfde9b9b90775e67f47d4a1c3482058" +
                        "efc9f40d2ca033a0801b63d45b3b722e" +
                        "f552bad3b4ccb667da350192b61c508c" +
                        "f7b6b5adadc2c8d9a446ef003fb05cba" +
                        "5f30e88e36ec2703b349ca229c267083" +
                        "3900"));
        assertThat(HexEncoder.getString(byteR), is("554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a080"));
        assertThat(HexEncoder.getString(byteS), is("1b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900"));
    }

    @Test
    public void success_SignMessage_8() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "2ec5fe3c17045abdb136a5e6a913e32a" +
                        "b75ae68b53d2fc149b77e504132d3756" +
                        "9b7e766ba74a19bd6162343a21c8590a" +
                        "a9cebca9014c636df5");
        KeyPair pair = generator.generateKeyPair(privateKey);
        Signature signature = scheme.getSigner().sign(pair, HexEncoder.getBytes(
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
                        "a69ccce38fabdf86f3bef6044819de11"), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(signature.getSignature()), is(
                "c650ddbb0601c19ca11439e1640dd931" +
                        "f43c518ea5bea70d3dcde5f4191fe53f" +
                        "00cf966546b72bcc7d58be2b9badef28" +
                        "743954e3a44a23f880e8d4f1cfce2d7a" +
                        "61452d26da05896f0a50da66a239a8a1" +
                        "88b6d825b3305ad77b73fbac0836ecc6" +
                        "0987fd08527c1a8e80d5823e65cafe2a" +
                        "3d00"));
        assertThat(HexEncoder.getString(byteR), is("c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880"));
        assertThat(HexEncoder.getString(byteS), is("e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00"));
    }

    @Test(expected = IllegalStateException.class)
    public void failure_SignMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);

        SecureRandom random = new SecureRandom();
        byte[] randomByte = new byte[256];
        random.nextBytes(randomByte);

        scheme.getSigner().sign(pair, HexEncoder.getBytes("03"), randomByte);
    }

    @Test(expected = IllegalStateException.class)
    public void failure_SignMessage_2() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "c4eab05d357007c632f3dbb48489924d" +
                        "552b08fe0c353a0d4a1f00acda2c463a" +
                        "fbea67c5e8d2877c5e3bc397a659949e" +
                        "f8021e954e0a12274e");
        KeyPair pair = generator.generateKeyPair(privateKey);

        SecureRandom random = new SecureRandom();
        byte[] randomByte = new byte[257];
        random.nextBytes(randomByte);

        scheme.getSigner().sign(pair, HexEncoder.getBytes("03"), randomByte);
    }

    @Test(expected = IllegalStateException.class)
    public void failure_TooLongContext() {
        byte[] context = new byte[256];
        KeyPair pair = generator.generateKeyPair();
        Signature signature = scheme.getSigner().sign(pair, "hoge".getBytes(), context);
    }
}
