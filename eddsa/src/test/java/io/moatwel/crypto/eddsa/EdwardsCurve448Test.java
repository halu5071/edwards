package io.moatwel.crypto.eddsa;

import org.junit.Before;
import org.junit.Test;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.KeyPair;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.PublicKey;
import io.moatwel.crypto.Signature;
import io.moatwel.crypto.eddsa.ed25519.Curve25519;
import io.moatwel.crypto.eddsa.ed25519.PrivateKeyEd25519;
import io.moatwel.crypto.eddsa.ed448.Ed448SchemeProvider;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class EdwardsCurve448Test {

    private Edwards edwards;

    @Before
    public void setup() {
        edwards = new Edwards(new Ed448SchemeProvider(HashAlgorithm.SHAKE_256));
    }

    @Test(expected = NullPointerException.class)
    public void failure_InstantiateEdwards() {
        SchemeProvider provider = null;
        new Edwards(provider);
    }

    @Test
    public void success_GeneratePublicKey_from_existing_privateKey() {
        PrivateKey privateKey = PrivateKey.newInstance(
                "6c82a562cb808d10d632be89c8513ebf" +
                        "6c929f34ddfa8c9f63c9960ef6e348a3" +
                        "528c8a3fcc2f044e39a3fc5b94492f8f" +
                        "032e7549a20098f95b");

        KeyPair pair = edwards.generateKeyPair(privateKey);

        assertThat(pair.getPrivateKey().getHexString(), is(
                "6c82a562cb808d10d632be89c8513ebf" +
                        "6c929f34ddfa8c9f63c9960ef6e348a3" +
                        "528c8a3fcc2f044e39a3fc5b94492f8f" +
                        "032e7549a20098f95b"));
        assertThat(pair.getPublicKey().getHexString(), is(
                "5fd7449b59b461fd2ce787ec616ad46a" +
                        "1da1342485a70e1f8a0ea75d80e96778" +
                        "edf124769b46c7061bd6783df1e50f6c" +
                        "d1fa1abeafe8256180"));

        Signature signature = edwards.sign(pair, "hogehoge".getBytes(), "entity".getBytes());

        boolean isValid1 = edwards.verify(pair, "hogehoge".getBytes(), "entity".getBytes(), signature);
        assertThat(isValid1, is(true));

        boolean isValid2 = edwards.verify(pair, "hogefuga".getBytes(), "entity".getBytes(), signature);
        assertThat(isValid2, is(false));

        boolean isValid3 = edwards.verify(pair, "hogehoge".getBytes(), "entiy".getBytes(), signature);
        assertThat(isValid3, is(false));

        boolean isValid4 = edwards.verify(pair, "hogefuga".getBytes(), "entiy".getBytes(), signature);
        assertThat(isValid4, is(false));
    }

    @Test(expected = IllegalStateException.class)
    public void failure_wrong_HashAlgorithm() {
        Edwards edwards = new Edwards(new Ed448SchemeProvider(HashAlgorithm.KECCAK_256));
        edwards.generateKeyPair();
    }
}