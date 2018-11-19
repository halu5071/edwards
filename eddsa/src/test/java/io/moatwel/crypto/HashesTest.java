package io.moatwel.crypto;

import org.junit.Test;

import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class HashesTest {

    @Test
    public void success_1() {
        String data = "demo";
        byte[] sha512 = Hashes.hash(HashAlgorithm.SHA_512, data.getBytes());
        byte[] keccakHash512 = Hashes.hash(HashAlgorithm.KECCAK_512, data.getBytes());
        byte[] keccakHash256 = Hashes.hash(HashAlgorithm.KECCAK_256, data.getBytes());
        byte[] emptyByteArray = Hashes.hash(HashAlgorithm.KECCAK_512, new byte[32]);
        byte[] emptySha512 = Hashes.hash(HashAlgorithm.SHA_512, new byte[32]);

        assertThat(HexEncoder.getString(sha512), is("26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"));
        assertThat(HexEncoder.getString(keccakHash512), is("fbf3b9980951aa921b8e30b782317a77a0dcc855551fd86720b1050bf8d40d30a07404021379a7bc8dbbcf8a4506c1c84db02e2e7a4441b80d154d1e7addb2fd"));
        assertThat(HexEncoder.getString(keccakHash256), is("3a784687a2b2ff9a2c72e22b001d33d9f2e2155a7858ff663b0990d35f14745d"));
        assertThat(HexEncoder.getString(emptyByteArray), is("0f6f7226432c21d4dfa2a1538a1fdc72ee1faf405a60e5f408b344a2f5aab2ddff0f9c172b6f7e2259b7929bce06388ecf84a51605bc48cd0b3c51d0eb12e3fa"));
        assertThat(HexEncoder.getString(emptySha512), is("5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1960a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3"));
    }

    @Test
    public void success_2() {
        byte[] input = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        byte[] input2 = new byte[]{1, 12, 23, 23, 74, 53, 6, 70, 38, 9, 10, 71, 72, 3, 54, 42, 96, 17, 18, 59, 20, 121, 32, 13, 24, 75, 26, 7, 18, 29, 90, 41};

        byte[] output = Hashes.hash(HashAlgorithm.KECCAK_512, input);
        byte[] output2 = Hashes.hash(HashAlgorithm.KECCAK_512, input2);

        assertThat(HexEncoder.getString(output), is("1414d219f4863f278acca4a4b5149298e2ec4f001d83f5f6e09fb14d7b47732e9ee6aaccbebedf2092b9cb209694b7eb8e7e36bbec9f9866a031d8901f891099"));
        assertThat(HexEncoder.getString(output2), is("ce7d397f3a74c602d6366ed0c6e868b0cf968e9986166323e02b83ef8bd891a9b8389b846eb88db32f0482e28744c56e3b471751f968d70c564eb3d7def2bf5b"));
    }

    @Test
    public void success_3() {
        String input = "lkadjlkfalkgnlaksdnfkladf";
        String input2 = "aklkl5028359gq94521nef8wdfank3l45134";
        String input3 = "9cv0we90t138tjapdfq84t1ndgowe9r12b51bsfdagldafk";

        byte[] output = Hashes.hash(HashAlgorithm.KECCAK_512, input.getBytes());
        byte[] output2 = Hashes.hash(HashAlgorithm.KECCAK_512, input2.getBytes());
        byte[] output3 = Hashes.hash(HashAlgorithm.KECCAK_512, input3.getBytes());
        assertThat(HexEncoder.getString(output), is("1f391471f9ad9c71a871ff3deb291d302351abd1c13a7aac09f465d7708fb1d5900ca2762064e89f97a0149a495c2657ff239fb5872d0a14cef25f130bc30cb6"));
        assertThat(HexEncoder.getString(output2), is("662d8fe0adf56b15f082f53ca28175176f39d244f3f84b3df96102edbfacf03721cd9ba9d4278ae69af650c9ef228ca98445b19dd23702cf1b6f52b9780f2eb3"));
        assertThat(HexEncoder.getString(output3), is("4dea7f98af31bbadc021fd9179830b23e29304b96b1f676ee52d06eaf1b6037a4203de65426b137456730896917e48e608014f29abd36ed53f4e85430f39fd2b"));
    }

    @Test
    public void success_4() {
        String seed = "ab4195d4123f0594e5341c45134c5938cc5913d34aa951234c5938cc2a6eb487";

        byte[] result3 = Hashes.hash(HashAlgorithm.SHA_512, HexEncoder.getBytes(seed));

        String result3Str = HexEncoder.getString(result3);

        assertThat(result3Str, is("fb51bcb380697c0fd1e1817b4faefff56d780f2609169d69aa7db8e7ae4bc830c2c2b0487bbe69be5f8ce1e3c52abd1ac81e99af98bab15f73b18469376dd375"));
    }

    @Test
    public void success_5() {
        String seed1 = "This is a pen.";
        String seed2 = "ed25519";
        String seed3 = "klf;ajdfa98";

        byte[] result1 = Hashes.hash(HashAlgorithm.SHA_512, seed1.getBytes());
        byte[] result2 = Hashes.hash(HashAlgorithm.SHA_512, seed2.getBytes());
        byte[] result3 = Hashes.hash(HashAlgorithm.SHA_512, seed3.getBytes());

        assertThat(HexEncoder.getString(result1), is("84b50c6166495578d74b5c0a333aae89990389b3d2895e480750ecf7e5f90200912ccc9b1cb4b0867811d6ffa0d3c6c343c37b1ca928b70124afcff6640bce78"));
        assertThat(HexEncoder.getString(result2), is("5bd5fc9297204890e536091937435f04c55bba9f21e8701837b144c6d8b6382d8cacfc1ea6cf5967ddac09e5f4cd213dc57870c2837a88765c076a2935782568"));
        assertThat(HexEncoder.getString(result3), is("80e21b76ffaf5755e60ea1486a7a201c058c88718299711c9ed09e75fc2ed31fc484e3b26e72e6c033b96135692e1970a0c89e2cf7dee8c57a4d3a5a45be509f"));
    }

    @Test
    public void success_6() {
        String seed1 = "abcdfa";
        String seed2 = "234fad";
        String seed3 = "daf1-3";

        byte[] bytes = ByteUtils.join(seed1.getBytes(), seed2.getBytes(), seed3.getBytes());
        byte[] result = Hashes.hash(HashAlgorithm.SHA_512, bytes);

        assertThat(HexEncoder.getString(result), is("69aaaf4b6fc82362212a611caff822be8bb4b8d246c3cd33474914690b32e2bc79da889adae033ecef441a1663028a64ec8f860fb039974bb1bb37500218d998"));
    }

    @Test
    public void success_7() {
        String seed1 = "ed25519";

        byte[] result1 = Hashes.hash(HashAlgorithm.SHAKE_256, seed1.getBytes(), 64);
        assertThat(HexEncoder.getString(result1), is("4670b3737cc4f03c97e005f447da7262359670bbfc72f16a50191a6b083df15aebe8ad55e1ec161b7b42fa6d1de20e2e426f0ca6c84899a13edacfdff47c788a"));

        byte[] result2 = Hashes.hash(HashAlgorithm.SHAKE_256, seed1.getBytes(), 65);
        assertThat(HexEncoder.getString(result2), is("4670b3737cc4f03c97e005f447da7262359670bbfc72f16a50191a6b083df15aebe8ad55e1ec161b7b42fa6d1de20e2e426f0ca6c84899a13edacfdff47c788a57"));
    }
}
