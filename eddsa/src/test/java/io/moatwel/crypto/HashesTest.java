package io.moatwel.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import io.moatwel.util.ByteUtils;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Hashes.class)
public class HashesTest {

    @Test
    public void success() {
        String data = "demo";
        byte[] sha3Hash256 = Hashes.sha3Hash256(data.getBytes());
        byte[] sha3Hash512 = Hashes.sha3Hash512(data.getBytes());
        byte[] ripemd160 = Hashes.ripemd160(data.getBytes());
        byte[] keccakHash512 = Hashes.hash(HashAlgorithm.KECCAK_512.getName(), data.getBytes());
        byte[] keccakHash256 = Hashes.hash(HashAlgorithm.KECCAK_256.getName(), data.getBytes());
        byte[] emptyByteArray = Hashes.hash(HashAlgorithm.KECCAK_512.getName(), new byte[32]);
        byte[] emptySha512 = Hashes.hash(HashAlgorithm.SHA_512.getName(), new byte[32]);

        assertThat(HexEncoder.getString(sha3Hash256), is("3a784687a2b2ff9a2c72e22b001d33d9f2e2155a7858ff663b0990d35f14745d"));
        assertThat(HexEncoder.getString(sha3Hash512), is("fbf3b9980951aa921b8e30b782317a77a0dcc855551fd86720b1050bf8d40d30a07404021379a7bc8dbbcf8a4506c1c84db02e2e7a4441b80d154d1e7addb2fd"));
        assertThat(HexEncoder.getString(ripemd160), is("6d910fb0460f1e2ae8546b099e34292f742b1a73"));
        assertThat(HexEncoder.getString(keccakHash512), is("fbf3b9980951aa921b8e30b782317a77a0dcc855551fd86720b1050bf8d40d30a07404021379a7bc8dbbcf8a4506c1c84db02e2e7a4441b80d154d1e7addb2fd"));
        assertThat(HexEncoder.getString(keccakHash256), is("3a784687a2b2ff9a2c72e22b001d33d9f2e2155a7858ff663b0990d35f14745d"));
        assertThat(HexEncoder.getString(emptyByteArray), is("0f6f7226432c21d4dfa2a1538a1fdc72ee1faf405a60e5f408b344a2f5aab2ddff0f9c172b6f7e2259b7929bce06388ecf84a51605bc48cd0b3c51d0eb12e3fa"));
        assertThat(HexEncoder.getString(emptySha512), is("5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1960a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3"));
    }

    @Test
    public void success_sha3Hash512_to_little_endian_integer() {
        byte[] input = new byte[32];
        byte[] data = new byte[15];

        byte[] r = Hashes.sha3Hash512(input, data);
        ByteBuffer buffer = ByteBuffer.wrap(r);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int result = buffer.getInt();

        System.out.println(new BigInteger(ByteUtils.reverse(r)));
        System.out.println(result);
    }
}
