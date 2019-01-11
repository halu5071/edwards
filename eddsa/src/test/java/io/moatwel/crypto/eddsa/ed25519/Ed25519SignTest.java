package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Before;
import org.junit.Test;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519SignTest {

    private KeyPair pair;
    private EdDsaSigner signer = new Ed25519Signer(HashAlgorithm.SHA_512, new Ed25519SchemeProvider(HashAlgorithm.SHA_512));

    @Before
    public void setup() {
        KeyGenerator generator = new EdDsaKeyGenerator(new Ed25519SchemeProvider(HashAlgorithm.SHA_512));
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("abd3df0ba4c941a451c934a44938cc2bf051233c4e535931233c4e5351a4c695");
        pair = generator.generateKeyPair(privateKey);

        assertThat(pair.getPublicKey().getHexString(), is("195ac5d462f0aa357c424982250f994ab0918ecee50a2ce5c6feb4f6b07ab660"));
    }

    @Test
    public void success_SignMessage_1() {
        Signature signature = signer.sign(pair, "demo".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("c213f4f628f493b9566f0ba99adfbd2c9e36ca70e8563786f524780399335801"));
        assertThat(HexEncoder.getString(byteR), is("840ce11e453af4c2e48fbec448b7de3957e167c16f8e72051c535dd75281e574"));
    }

    @Test
    public void success_SignMessage_2() {
        Signature signature = signer.sign(pair, "ed25519".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("b6cf62ad25f93f2ef34c49777946b0c10305b58b3a8374d9f77641e56da1b400"));
        assertThat(HexEncoder.getString(byteR), is("6c543c13177252112541e3382e5b73be26a5360e68459c87604ac53b8ac1cfcb"));
    }

    @Test
    public void success_SignMessage_3() {
        Signature signature = signer.sign(pair, "klf;ajdfa98".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("a20b143bc1b6637f8dd3cd0fffe5d3c2eb566bc3441fe965e7d96aa60f9e3204"));
        assertThat(HexEncoder.getString(byteR), is("0b67a11b2564accd38d9b963ac22eb64ed2ec9c17de25f7fe3209afc21886702"));
    }

    @Test
    public void success_SignMessage_4() {
        Signature signature = signer.sign(pair, "This is it.".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("5ee928c567ca94c7e03b444ed2302c8ef2b721ccfc3faec2f1258ce92cc3fa04"));
        assertThat(HexEncoder.getString(byteR), is("24a2101437ae0680dc1425e0fc43ad7bbcfeec01ec4831b3907290d5443e5296"));
    }

    @Test
    public void success_SignMessage_5() {
        Signature signature = signer.sign(pair, "!@#$@#Sample".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("d21ed20b83fa621f90cbc12b4dda8d359ea46bb8b4a3346a4ef26575434dcf0a"));
        assertThat(HexEncoder.getString(byteR), is("733a5fd918641e66450684849d5347daad7b3d1649f29be6fead893a99912840"));
    }

    @Test
    public void success_SignMessage_6() {
        Signature signature = signer.sign(pair, "!@k;adfadslkfjd98fle".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("d4912c81039057f9ac0c06b2cdf3893c5487e03872d03935419a70faa11a4103"));
        assertThat(HexEncoder.getString(byteR), is("21b39002c3d32323b675cee45c83ed41a98cfb4dca70ddd8387bc9cc0cc54719"));
    }

    @Test
    public void success_SignMessage_7() {
        Signature signature = signer.sign(pair, "1092834dfakfjd98fle".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("0fe21d8ec1f9c9f858123909fc6ec0413bd7713ef2fc86dc4b8afb5822661309"));
        assertThat(HexEncoder.getString(byteR), is("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));
    }

    @Test
    public void success_SignMessage_8() {
        Signature signature = signer.sign(pair, "099adpktr=2q3jpdaf asl;dkf9".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("cfdab92cba5daa36ce23b23333c7525f924d708ee5d5dd9161306a22d4328c03"));
        assertThat(HexEncoder.getString(byteR), is("899c9d230f24d416647b0cfa04edc8158bb87bcd4332901cda27a979d8132a99"));
    }

    @Test
    public void success_SignMessage_9() {
        Signature signature = signer.sign(pair, "klad -ifadsopfi ad9ufq4fasdt   24r".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("bfddc40489623f1c48277dafaa1b5ba0eaa9649b86a6ff062bd1df2850f62e0d"));
        assertThat(HexEncoder.getString(byteR), is("a13f3a02cc97ec252b785702ce5f1a201a0fc7dd177c636c5f97482af7294f5f"));
    }

    @Test
    public void success_SignMessage_10() {
        Signature signature = signer.sign(pair, "09a[sp i9-a0r90q 90i [qi309qu3r9".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("c270a4ab74e4989ad600f553664a97224059b8b8f374edd951a43d8ae809e001"));
        assertThat(HexEncoder.getString(byteR), is("ebb7b4086e62dfd02dc01ab9c5c05828beb0756207aafd74a9ffc9f506f544fb"));
    }

    @Test
    public void success_SignMessage_11() {
        Signature signature = signer.sign(pair, "0lafoaidalkfagahidof".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("125b2e33ab2c494cdaeccd7c4067b06a0094a3601b233f60c39ac3b156d83d09"));
        assertThat(HexEncoder.getString(byteR), is("0a188e7c2d198cac458d2001f28d17eb6fd9f06ba169f4117f4eb6ee25e01058"));
    }

    @Test
    public void success_SignMessage_12() {
        Signature signature = signer.sign(pair, "Are You Sleeping Brother John".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("b768727a65bd47384c563d4442acc4566480310d8df1544f0749bb009f01b906"));
        assertThat(HexEncoder.getString(byteR), is("7dc00bd331c30d033af3b7e5f8369edb3528e883e34836d622ed44b8845c2a63"));
    }

    @Test
    public void success_SignMessage_13() {
        Signature signature = signer.sign(pair, "One day in summer, when a grasshopper was singing in the grassy meadow, a group of ants walked by.".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("807634a27246bbecd32b37fafb1b1f82140cb8428b77c2197c1061d6954eb60f"));
        assertThat(HexEncoder.getString(byteR), is("1c8dc594082e7ddad6a97f500247a585993d3b1a797041ce6f203902a7816833"));
    }

    @Test
    public void success_SignMessage_14() {
        Signature signature = signer.sign(pair, "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. Four-score Men and Four-score more, Could not make Humpty Dumpty where he was before.".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("fbe627802438e90fe5159f08106faaf828100be3cd3d962a50f2353dcf07350b"));
        assertThat(HexEncoder.getString(byteR), is("b195102f70426e51c8e8ed0e31e74447e0b461a85e1ec14397bb88acbcfc15c8"));
    }

    @Test
    public void success_SignMessage_15() {
        Signature signature = signer.sign(pair, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("69e5160bdff2a2bac6d6a6199b70f9c80346359a2cc6bf15c53901b46189a50d"));
        assertThat(HexEncoder.getString(byteR), is("2907562747a75308d8933147985aa74245e65a37de15b0d408e51f712d94b37d"));
    }

    @Test
    public void success_SignMessage_16() {
        Signature signature = signer.sign(pair, "There was once a rich man whose wife lay sick, and when she felt her end drawing near she called to her only daughter to come near her bed".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("df2780568c569c6713ed48bc7d96e04a93fdda45237bfc34afe40518b2635f02"));
        assertThat(HexEncoder.getString(byteR), is("0a7839c8658c2186c5650644ee832c092cb46bff7c6a777621567dd5c9e8c8c3"));
    }

    @Test
    public void success_SignMessage_17() {
        Signature signature = signer.sign(pair, "Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag being 1".getBytes(), null);

        byte[] byteS = signature.getS();
        byte[] byteR = signature.getR();

        assertThat(HexEncoder.getString(byteS), is("3d1e56d8b2056234a601126871ea8d87a7bc70b66dc944e2ab3b1d22f70b4b00"));
        assertThat(HexEncoder.getString(byteR), is("100027018c8eeac626c5f78ac3f79cd2469d51336f859736291c030b879d9e43"));
    }
}
