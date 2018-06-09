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

        assertThat(HexEncoder.getString(sha3Hash256), is("7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"));
        assertThat(HexEncoder.getString(sha3Hash512), is("a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"));
        assertThat(HexEncoder.getString(ripemd160), is("6d910fb0460f1e2ae8546b099e34292f742b1a73"));
    }

    @Test
    public void success_sha3Hash512_to_little_endian_integer() {
        byte[] input = new byte[32];
        byte[] data = new byte[15];

        byte[] r = Hashes.sha3Hash512(ByteUtils.join(input, data));
        ByteBuffer buffer = ByteBuffer.wrap(r);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int result = buffer.getInt();

        System.out.println(new BigInteger(ByteUtils.reverse(r)));
        System.out.println(result);
    }
}
