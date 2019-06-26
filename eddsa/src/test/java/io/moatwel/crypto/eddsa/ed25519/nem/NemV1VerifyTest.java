package io.moatwel.crypto.eddsa.ed25519.nem;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.Edwards;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class NemV1VerifyTest {

    private KeyPair pair;
    private Edwards edwards = new Edwards(new NemV1SchemeProvider());

    @Before
    public void setup() {
        PrivateKey privateKey = PrivateKey.newInstance("a958255dbd7d642fa4fac6c775f2ee667340f5d005b1459f74c7d1c186ddc46a");
        pair = edwards.generateKeyPair(privateKey);
    }

    @Test
    public void success_VerifySignature_1() {
        Signature signature = edwards.sign(pair, "demo".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "demo".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_2() {
        Signature signature = edwards.sign(pair, "This is it.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "This is it.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_3() {
        Signature signature = edwards.sign(pair, "klf;ajdfa98".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "klf;ajdfa98".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_4() {
        Signature signature = edwards.sign(pair, "ed25519".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "ed25519".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_5() {
        Signature signature = edwards.sign(pair, "!@#$@#Sample".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "!@#$@#Sample".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_6() {
        Signature signature = edwards.sign(pair, "1092834dfakfjd98fle".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "1092834dfakfjd98fle".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_7() {
        Signature signature = edwards.sign(pair, "09a[sp i9-a0r90q 90i [qi309qu3r9".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "09a[sp i9-a0r90q 90i [qi309qu3r9".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_8() {
        Signature signature = edwards.sign(pair, "Are You Sleeping Brother John".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Are You Sleeping Brother John".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_9() {
        Signature signature = edwards.sign(pair, "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. Four-score Men and Four-score more, Could not make Humpty Dumpty where he was before.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. Four-score Men and Four-score more, Could not make Humpty Dumpty where he was before.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_10() {
        Signature signature = edwards.sign(pair, "There was once a rich man whose wife lay sick, and when she felt her end drawing near she called to her only daughter to come near her bed".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "There was once a rich man whose wife lay sick, and when she felt her end drawing near she called to her only daughter to come near her bed".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_11() {
        Signature signature = edwards.sign(pair, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_12() {
        Signature signature = edwards.sign(pair, "Check the group equation [8][S]B = [8]R + [8][k]A'.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Check the group equation [8][S]B = [8]R + [8][k]A'.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_13() {
        Signature signature = edwards.sign(pair, "Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag being 1".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag being 1".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_14() {
        Signature signature = edwards.sign(pair, "When Harry knocked they heard a frantic scrabbling from inside and several booming barks.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "When Harry knocked they heard a frantic scrabbling from inside and several booming barks.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_15() {
        Signature signature = edwards.sign(pair, "And when the evening came she wanted to go home, but the prince said he would go with her to take care of her, for he wanted to see where the beautiful maiden lived.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "And when the evening came she wanted to go home, but the prince said he would go with her to take care of her, for he wanted to see where the beautiful maiden lived.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_16() {
        Signature signature = edwards.sign(pair, "Hush, little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Hush, little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_17() {
        Signature signature = edwards.sign(pair, "London Bridge is broken down,　Broken down, broken down.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "London Bridge is broken down,　Broken down, broken down.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_18() {
        Signature signature = edwards.sign(pair, "Peter Piper picked a peck of pickled peppers.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Peter Piper picked a peck of pickled peppers.".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_19() {
        Signature signature = edwards.sign(pair, "This is the farmer sowing his corn, that kept the cock that crowed in the morn, that waked the priest all shaven and shorn, that married the man all tattered and torn, that kissed the maiden all forlorn, that milked the cow with the crumpled horn".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "This is the farmer sowing his corn, that kept the cock that crowed in the morn, that waked the priest all shaven and shorn, that married the man all tattered and torn, that kissed the maiden all forlorn, that milked the cow with the crumpled horn".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_20() {
        Signature signature = edwards.sign(pair, "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do".getBytes(), null, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void success_VerifySignature_21() {
        SecureRandom random = new SecureRandom();
        byte[] context = new byte[255];
        random.nextBytes(context);
        Signature signature = edwards.sign(pair, "alice".getBytes(), context);

        boolean isVerified = edwards.verify(pair, "alice".getBytes(), context, signature);

        assertThat(isVerified, is(true));
    }

    @Test
    public void failure_VerifySignature_1() {
        Signature signature = edwards.sign(pair, "demo".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "demo.".getBytes(), null, signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifySignature_2() {
        Signature signature = edwards.sign(pair, "This is it.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "This is it".getBytes(), null, signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifySignature_3() {
        Signature signature = edwards.sign(pair, "klf;ajdfa98".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "klf;ajdfa98d".getBytes(), null, signature);

        assertThat(isVerified, is(false));
    }

    @Test
    public void failure_VerifySignature_16() {
        Signature signature = edwards.sign(pair, "Hush, little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes(), null);

        boolean isVerified = edwards.verify(pair, "Hush,  little baby, don't say a word,　Mama's going to buy you a mockingbird.".getBytes(), null, signature);

        assertThat(isVerified, is(false));
    }

    @Test(expected = IllegalStateException.class)
    public void failure_TooLongContext() {
        byte[] context = new byte[256];

        Signature signature = edwards.sign(pair, "doctor".getBytes(), null);
        edwards.verify(pair, "doctor".getBytes(), context, signature);
    }
}
