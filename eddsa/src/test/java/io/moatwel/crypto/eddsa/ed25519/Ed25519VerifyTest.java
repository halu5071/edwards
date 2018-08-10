package io.moatwel.crypto.eddsa.ed25519;

import io.moatwel.crypto.*;
import io.moatwel.crypto.eddsa.EdDsaKeyGenerator;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519VerifyTest {

    private KeyPair pair;
    private EdDsaSigner signer = new Ed25519Signer(HashAlgorithm.SHA_512);

    @Before
    public void setup() {
        KeyGenerator generator = new EdDsaKeyGenerator(new Ed25519CurveProvider(HashAlgorithm.SHA_512));
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("abd3df0ba4c941a451c934a44938cc2bf051233c4e535931233c4e5351a4c695");
        pair = generator.generateKeyPair(privateKey);

        assertThat(pair.getPublicKey().getHexString(), is("195ac5d462f0aa357c424982250f994ab0918ecee50a2ce5c6feb4f6b07ab660"));
    }

    @Test
    public void success_VerifySignature_1() {
        Signature signature = signer.sign(pair, "demo".getBytes());

        boolean isVerified = signer.verify(pair, "demo".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_2() {
        Signature signature = signer.sign(pair, "This is it.".getBytes());

        boolean isVerified = signer.verify(pair, "This is it.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_3() {
        Signature signature = signer.sign(pair, "klf;ajdfa98".getBytes());

        boolean isVerified = signer.verify(pair, "klf;ajdfa98".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_4() {
        Signature signature = signer.sign(pair, "ed25519".getBytes());

        boolean isVerified = signer.verify(pair, "ed25519".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_5() {
        Signature signature = signer.sign(pair, "!@#$@#Sample".getBytes());

        boolean isVerified = signer.verify(pair, "!@#$@#Sample".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_6() {
        Signature signature = signer.sign(pair, "1092834dfakfjd98fle".getBytes());

        boolean isVerified = signer.verify(pair, "1092834dfakfjd98fle".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_7() {
        Signature signature = signer.sign(pair, "09a[sp i9-a0r90q 90i [qi309qu3r9".getBytes());

        boolean isVerified = signer.verify(pair, "09a[sp i9-a0r90q 90i [qi309qu3r9".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_8() {
        Signature signature = signer.sign(pair, "Are You Sleeping Brother John".getBytes());

        boolean isVerified = signer.verify(pair, "Are You Sleeping Brother John".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_9() {
        Signature signature = signer.sign(pair, "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. Four-score Men and Four-score more, Could not make Humpty Dumpty where he was before.".getBytes());

        boolean isVerified = signer.verify(pair, "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. Four-score Men and Four-score more, Could not make Humpty Dumpty where he was before.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_10() {
        Signature signature = signer.sign(pair, "There was once a rich man whose wife lay sick, and when she felt her end drawing near she called to her only daughter to come near her bed".getBytes());

        boolean isVerified = signer.verify(pair, "There was once a rich man whose wife lay sick, and when she felt her end drawing near she called to her only daughter to come near her bed".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_11() {
        Signature signature = signer.sign(pair, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes());

        boolean isVerified = signer.verify(pair, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_12() {
        Signature signature = signer.sign(pair, "Check the group equation [8][S]B = [8]R + [8][k]A'.".getBytes());

        boolean isVerified = signer.verify(pair, "Check the group equation [8][S]B = [8]R + [8][k]A'.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_13() {
        Signature signature = signer.sign(pair, "Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag being 1".getBytes());

        boolean isVerified = signer.verify(pair, "Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag being 1".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_14() {
        Signature signature = signer.sign(pair, "When Harry knocked they heard a frantic scrabbling from inside and several booming barks.".getBytes());

        boolean isVerified = signer.verify(pair, "When Harry knocked they heard a frantic scrabbling from inside and several booming barks.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_15() {
        Signature signature = signer.sign(pair, "And when the evening came she wanted to go home, but the prince said he would go with her to take care of her, for he wanted to see where the beautiful maiden lived.".getBytes());

        boolean isVerified = signer.verify(pair, "And when the evening came she wanted to go home, but the prince said he would go with her to take care of her, for he wanted to see where the beautiful maiden lived.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_16() {
        Signature signature = signer.sign(pair, "Hush, little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes());

        boolean isVerified = signer.verify(pair, "Hush, little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_17() {
        Signature signature = signer.sign(pair, "London Bridge is broken down,　Broken down, broken down.".getBytes());

        boolean isVerified = signer.verify(pair, "London Bridge is broken down,　Broken down, broken down.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_18() {
        Signature signature = signer.sign(pair, "Peter Piper picked a peck of pickled peppers.".getBytes());

        boolean isVerified = signer.verify(pair, "Peter Piper picked a peck of pickled peppers.".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_19() {
        Signature signature = signer.sign(pair, "This is the farmer sowing his corn, that kept the cock that crowed in the morn, that waked the priest all shaven and shorn, that married the man all tattered and torn, that kissed the maiden all forlorn, that milked the cow with the crumpled horn".getBytes());

        boolean isVerified = signer.verify(pair, "This is the farmer sowing his corn, that kept the cock that crowed in the morn, that waked the priest all shaven and shorn, that married the man all tattered and torn, that kissed the maiden all forlorn, that milked the cow with the crumpled horn".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_20() {
        Signature signature = signer.sign(pair, "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do".getBytes());

        boolean isVerified = signer.verify(pair, "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do".getBytes(), signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void failure_VerifySignature_1() {
        Signature signature = signer.sign(pair, "demo".getBytes());

        boolean isVerified = signer.verify(pair, "demo.".getBytes(), signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifySignature_2() {
        Signature signature = signer.sign(pair, "This is it.".getBytes());

        boolean isVerified = signer.verify(pair, "This is it".getBytes(), signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifySignature_3() {
        Signature signature = signer.sign(pair, "klf;ajdfa98".getBytes());

        boolean isVerified = signer.verify(pair, "klf;ajdfa98d".getBytes(), signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifySignature_16() {
        Signature signature = signer.sign(pair, "Hush, little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes());

        boolean isVerified = signer.verify(pair, "Hush,  little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes(), signature);

        assertThat(isVerified, is(false));
    }
}
