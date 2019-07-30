package io.moatwel.crypto.eddsa.ed448.ph;

import io.moatwel.crypto.*;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.ed448.Ed448Signer;
import io.moatwel.util.HexEncoder;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed448SignTest {

    private Edwards edwards;
    private EdDsaSigner signer = new Ed448Signer(HashAlgorithm.SHAKE_256, new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256));

    @Before
    public void setup() {
        edwards = new Edwards(new Ed448phSchemeProvider(HashAlgorithm.SHAKE_256));
    }

    @Test
    public void success_SignMessage_1() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "833fe62409237b9d62ec77587520911e" +
                        "9a759cec1d19755b7da901b96dca3d42" +
                        "ef7822e0d5104127dc05d6dbefde69e3" +
                        "ab2cec7c867c6e2c49");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is(
                "259b71c19f83ef77a7abd26524cbdb31" +
                        "61b590a48f7d17de3ee0ba9c52beb743" +
                        "c09428a131d6b1b57303d90d8132c276" +
                        "d5ed3d5d01c0f53880"));

        byte[] message = HexEncoder.getBytes("616263");
        Signature signature = signer.sign(keyPair, message, null);

        assertThat(signature.asString(), is(
                "822f6901f7480f3d5f562c592994d969" +
                        "3602875614483256505600bbc281ae38" +
                        "1f54d6bce2ea911574932f52a4e6cadd" +
                        "78769375ec3ffd1b801a0d9b3f4030cd" +
                        "433964b6457ea39476511214f97469b5" +
                        "7dd32dbc560a9a94d00bff07620464a3" +
                        "ad203df7dc7ce360c3cd3696d9d9fab9" +
                        "0f00"));
    }

    @Test
    public void success_SignMessage_2() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "833fe62409237b9d62ec77587520911e" +
                        "9a759cec1d19755b7da901b96dca3d42" +
                        "ef7822e0d5104127dc05d6dbefde69e3" +
                        "ab2cec7c867c6e2c49");
        KeyPair keyPair = edwards.generateKeyPair(privateKey);

        assertThat(keyPair.getPublicKey().getHexString(), is(
                "259b71c19f83ef77a7abd26524cbdb31" +
                        "61b590a48f7d17de3ee0ba9c52beb743" +
                        "c09428a131d6b1b57303d90d8132c276" +
                        "d5ed3d5d01c0f53880"));

        byte[] message = HexEncoder.getBytes("616263");
        byte[] context = HexEncoder.getBytes("666f6f");
        Signature signature = signer.sign(keyPair, message, context);

        assertThat(signature.asString(), is(
                "c32299d46ec8ff02b54540982814dce9" +
                        "a05812f81962b649d528095916a2aa48" +
                        "1065b1580423ef927ecf0af5888f90da" +
                        "0f6a9a85ad5dc3f280d91224ba9911a3" +
                        "653d00e484e2ce232521481c8658df30" +
                        "4bb7745a73514cdb9bf3e15784ab7128" +
                        "4f8d0704a608c54a6b62d97beb511d13" +
                        "2100"));
    }
}
