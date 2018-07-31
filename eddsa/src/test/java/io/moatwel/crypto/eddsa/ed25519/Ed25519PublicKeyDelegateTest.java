package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.Hashes;
import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.PublicKeyDelegate;
import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Ed25519PublicKeyDelegateTest {

    private PublicKeyDelegate delegate = new Ed25519PublicKeyDelegate(HashAlgorithm.KECCAK_512);
    private Curve curve = Ed25519Curve.getCurve();

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_byte_array_1() {
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(new byte[32]);

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        byte[] value = new byte[]{70, 46, -23, 118, -119, 9, 22, -27, 79, -88, 37, -46, 107,
                -35, 2, 53, -11, -21, 91, 106, 20, 60, 25, -102, -80, -82, 94, -23, 50, -114, 8, -50};

        assertThat(HexEncoder.getString(value), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
        assertThat(seed, is(value));
        assertThat(HexEncoder.getString(seed), is("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_byte_array_2() {
        byte[] input = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);
        String str = HexEncoder.getString(input);
        assertThat(str, is("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("a5840d03f4f3b879f53f8511ba19f0ba7cfbb4c62c254822ccd2470235f0548e"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_byte_array_3() {
        byte[] input = new byte[]{1, 12, 23, 23, 74, 53, 6, 70, 38, 9, 10, 71, 72, 3, 54, 42, 96, 17, 18, 59, 20, 121, 32, 13, 24, 75, 26, 7, 18, 29, 90, 41};
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("e8cd865136cffc97f7637addb27865ff85af3da1ad9dbee40da974ca5bbed111"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_hex_string_1() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("d5dc926cec6a4ad6d6e1322b1c249ad08b1ca1e54b190adcfb1ed56e9078bbd7");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("71a0d0c6d77f76bc6a0ccde4b7293395962435c13d8fcd86c585ca8a8f2eddb3"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_hex_string_2() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("25606d80d94ba30aa2fa25709eba75515c5e480c3c9e7d9dcefd08a01909ef97");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("57c9d82d5856f1634f535f8d9774215fcffa3d04e5fd441c7ede5fab03c104c2"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_hex_string_3() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("79241bfd22d6744341d57c600648711a83a06803fd4859488fe78f5e8d31f567");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("f1b230afee2486a873e06a23f3455708fa0cabce67149c507cff5649d07eb24f"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_hex_string_4() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("accbe57051b453cb00bb7e7d95d0b893d8730f05eeaa65329e4bfebb70319f98");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("e3286b65a39e17f622407ec080db5732c9de3f74b1d8075d0f0240458f77d197"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_KECCAK_512_from_hex_string_5() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("884c962b99a3bf997b0e25e2762856714d9e3d18cf4a9998f2ae032c7615dd6c");

        byte[] seed = delegate.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("6a12e5b9a9c8494f8e3c7c8af3b54d3b72c33d21fc80271fa54d44620663e58a"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_1() {
        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(new byte[32]);

        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        byte[] value = new byte[]{59, 106, 39, -68, -50, -74, -92, 45, 98, -93, -88, -48, 42
                , 111, 13, 115, 101, 50, 21, 119, 29, -30, 67, -90, 58, -64, 72, -95, -117, 89, -38, 41};

        assertThat(HexEncoder.getString(value), is("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"));
        assertThat(seed, is(value));
        assertThat(HexEncoder.getString(seed), is("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"));
    }


    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_byte_array_1() {
        byte[] input = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        String str = HexEncoder.getString(input);
        assertThat(str, is("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        assertThat(HexEncoder.getBytes(str), is(input));

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_byte_array_2() {
        byte[] input = new byte[]{10, -1, 12, 3, 24, 5, 62, 7, 82, 9, 17, 111, 62, -83, 14, 25, 123, 17, 18, -19, 20, 1, -22, 63, 24, -75, 26, 77, 28, 9, 30, 71};
        String str = HexEncoder.getString(input);
        assertThat(str, is("0aff0c0318053e075209116f3ead0e197b1112ed1401ea3f18b51a4d1c091e47"));
        assertThat(HexEncoder.getBytes(str), is(input));

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("6caba0ffd7da15129b9aaeb3021c4a6612f6ad3099ea3d90993a60f585243b23"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_byte_array_3() {
        byte[] input = new byte[]{19, -16, 82, 23, 24, -5, 62, 17, 82, 3, 67, 121, -16, -83, 14, 25, -13, 37, 13, -19, 20, 21, -82, 3, 94, -5, 26, 57, 18, 91, 110, 78};
        String str = HexEncoder.getString(input);
        assertThat(str, is("13f0521718fb3e1152034379f0ad0e19f3250ded1415ae035efb1a39125b6e4e"));
        assertThat(HexEncoder.getBytes(str), is(input));

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("6158e2b8e2ba640375e64b680a239f5df6211791f5858b1348423f88b134b9c8"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_byte_array_4() {
        byte[] input = new byte[]{17, 46, -22, 33, 94, -15, -22, 27, 112, 32, 57, 1, -16, 3, 44, 45, -13, -37, 43, 59, 2, -21, -2, 31, 14, -9, 46, 47, -18, 41, -10, 11};
        String str = HexEncoder.getString(input);
        assertThat(str, is("112eea215ef1ea1b70203901f0032c2df3db2b3b02ebfe1f0ef72e2fee29f60b"));
        assertThat(HexEncoder.getBytes(str), is(input));

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("91fa74ddee42574563acc2579f5e782d618d913b1cec2574e000b7768b462701"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_byte_array_5() {
        byte[] input = new byte[]{-82, 4, -22, 3, 94, -115, -22, 27, 12, 35, -14, 1, -26, 3, -44, 13, -113, -31, 93, 29, 2, -33, -72, 42, 14, -9, 13, 40, -28, 79, -13, 38};
        String str = HexEncoder.getString(input);
        assertThat(str, is("ae04ea035e8dea1b0c23f201e603d40d8fe15d1d02dfb82a0ef70d28e44ff326"));
        assertThat(HexEncoder.getBytes(str), is(input));

        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(input);

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("6daa7036e3ff1aa3fabb2a01b0b7e90c946f678df105da32bdd329593d3cbe3b"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_1() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487");

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("9b69ec0a4568848ec9bd9190996fce5a5f46d0a8eb20cdd770953e61855438ef"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_2() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("ab9d6ed9642b1a34c9938cc2a4123f0594e5341a45134c693bcc5934df0ba4c7");

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("5ff5d819b2a0b07ba2db275331def8fd32fb0b463a17e798a9aa87dc6245f079"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_3() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("abd3df0ba4c941a451c934a44938cc2bf051233c4e535931233c4e5351a4c695");

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("195ac5d462f0aa357c424982250f994ab0918ecee50a2ce5c6feb4f6b07ab660"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_4() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("93c2438333d31c4ac4f05c53cc2ab695d294f0ba451c1531a4e5b35914a449e3");

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("9553153da51781058489628fc538e1985522741de0d6162106c7d6d0243f1454"));
    }

    @Test
    public void success_GeneratePublicKeySeed_via_SHA_512_from_hex_string_5() {
        PrivateKey privateKey = PrivateKeyEd25519.fromHexString("4b325d1c1c4b5c53ce5b35f0153d32ab694f0b3c9e391a4414a444f7383339ac");

        PublicKeyDelegate delegate1 = new Ed25519PublicKeyDelegate(HashAlgorithm.SHA_512);
        byte[] seed = delegate1.generatePublicKeySeed(privateKey);

        assertThat(HexEncoder.getString(seed), is("6cf7c8ecd9de399fe992cd4dca5362b51c11183850f66f85e446d73ee323a582"));
    }

    @Test
    public void success_ScalarMultipliedBasePoint() {
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(new byte[32]);
        byte[] h = Hashes.hash(HashAlgorithm.SHA_512, privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        Point point = curve.getBasePoint().scalarMultiply(s);
        BigInteger x = point.getX().getInteger();
        BigInteger y = point.getY().getInteger();

        assertThat(x, is(new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616")));
        assertThat(y, is(new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291")));
    }

    @Test
    public void success_ScalarMultipliedBasePoint_2() {
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(new byte[32]);
        byte[] h = Hashes.hash(HashAlgorithm.SHA_512, privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        Point point = curve.getBasePoint().scalarMultiply(s);
        BigInteger x = point.getX().getInteger();
        BigInteger y = point.getY().getInteger();

        assertThat(x, is(new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616")));
        assertThat(y, is(new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291")));
    }

    @Test
    public void success_GenerateScalarA() {
        PrivateKey privateKey = PrivateKeyEd25519.fromBytes(new byte[32]);
        byte[] h = Hashes.hash(HashAlgorithm.SHA_512, privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        // Step2
        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        // Step3
        byte[] a = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(a);

        assertThat(s, is(new BigInteger("39325648866980652792715009169219496062012184734522019333892538943312776480336")));
    }
}
