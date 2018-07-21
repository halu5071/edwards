package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.EdDsaSigner;
import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyGenerator;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519SignerTest {

    private KeyPair pair;
    private EdDsaSigner signer = new Ed25519Signer(HashAlgorithm.SHA_512);

    @Before
    public void setup() {
        KeyGenerator generator = new EdDsaKeyGenerator(new Ed25519Provider(HashAlgorithm.SHA_512));
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("abd3df0ba4c941a451c934a44938cc2bf051233c4e535931233c4e5351a4c695");
        pair = generator.generateKeyPair(privateKey);

        assertThat(pair.getPublicKey().getHexString(), is("195ac5d462f0aa357c424982250f994ab0918ecee50a2ce5c6feb4f6b07ab660"));
    }

    @Test
    public void success_SignMessage_1() {
        Signature signature = signer.sign(pair, "demo".getBytes());

        BigInteger S1 = new BigInteger(signature.getBinaryS());

        assertThat(S1, is(new BigInteger("608151504584652004853499240773494238626613765402164003216414805396322259906")));
    }

    @Test
    public void success_SignMessage_2() {
        Signature signature = signer.sign(pair, "ed25519".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("1995176937022298200148328816722441379171870262442300318624442553462554985535")));
        // 319146615599574595135908926944340520491598694492366832960461172005503422390
    }

    @Test
    public void success_SignMessage_3() {
        Signature signature = signer.sign(pair, "klf;ajdfa98".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("1898684645419774132124924613741796942065819270747333085061629039735634922402")));
    }

    @Test
    public void success_SignMessage_4() {
        Signature signature = signer.sign(pair, "This is it.".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("2943014367778110947782890339301604547081485659022615626866226355528774794744")));
        // 2252310211898356742998600270025710650492586984677205696869814236970115197278
    }

    @Test
    public void success_SignMessage_5() {
        Signature signature = signer.sign(pair, "!@#$@#Sample".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("4889399081390395498979834532955498367300115987389662782867463763797495389906")));
    }

    @Test
    public void success_SignMessage_6() {
        Signature signature = signer.sign(pair, "!@k;adfadslkfjd98fle".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("1471967417291219034974179914450918877525039738523048696858314762487516139988")));
    }

    @Test
    public void success_SignMessage_7() {
        Signature signature = signer.sign(pair, "1092834dfakfjd98fle".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("7017698416601377673950188462492873541854737310876222100475461513227521634540")));
        // 4105090635616705429695061053659558245554003651275941563464146285782036767247
    }

    @Test
    public void success_SignMessage_8() {
        Signature signature = signer.sign(pair, "099adpktr=2q3jpdaf asl;dkf9".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("2982216749777705330497516584250259137707965746980732630976746333916954123539")));
        // 1604647941269107468368228687487870742511952935958022539608874018737074330319
    }

    @Test
    public void success_SignMessage_9() {
        Signature signature = signer.sign(pair, "klad -ifadsopfi ad9ufq4fasdt   24r".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("4335326486093165799423718745434855349075149576265308048517288203674762923710")));
        // 5963041987263877244708113770479269232811306164634722801487290783357877935551
    }

    @Test
    public void success_SignMessage_10() {
        Signature signature = signer.sign(pair, "09a[sp i9-a0r90q 90i [qi309qu3r9".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("2081074351875655504988229640638351001529496072963904273722212754264210046298")));
        // 848154976076826618610609638126270980845883908127446877491542198494102319298
    }

    @Test
    public void success_SignMessage_11() {
        Signature signature = signer.sign(pair, "0lafoaidalkfagahidof".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("4180086422687941743555252449907370113787776224591874379620126107137328700178")));
    }

    @Test
    public void success_SignMessage_12() {
        Signature signature = signer.sign(pair, "Are You Sleeping Brother John".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("3040754986938510989145289562253546463820345938239786637408821759298214455479")));
    }

    @Test
    public void success_SignMessage_13() {
        Signature signature = signer.sign(pair, "One day in summer, when a grasshopper was singing in the grassy meadow, a group of ants walked by.".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("5479085769191813790307601822450508738535981692614166226405967952343555663743")));
        // 7106801270362525235591996847494922622272138280983580979375970532026670675584
    }

    @Test
    public void success_SignMessage_14() {
        Signature signature = signer.sign(pair, "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. Four-score Men and Four-score more, Could not make Humpty Dumpty where he was before.".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("1669867259721994660982060332263791381045061732981975213671107445780037359037")));
        // 5069138128228814385089001217078374320204635670412237807821416353815958382331
    }

    @Test
    public void success_SignMessage_15() {
        Signature signature = signer.sign(pair, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes());

        BigInteger S2 = new BigInteger(signature.getBinaryS());

        assertThat(S2, is(new BigInteger("6172544970591950193155872168137672755394959546554192178812447797250218190185")));
    }
}
