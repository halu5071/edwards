package io.moatwel.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import io.moatwel.util.HexEncoder;

/**
 *
 * @author halu5071 (Yasunori Horii) at 2018/5/28
 */
public class PrivateKey {

    private final byte[] value;

    private PrivateKey(BigInteger integer) {
        this(integer.toByteArray());
    }

    private PrivateKey(byte[] value) {
        this.value = value;
    }

    public byte[] getRaw() {
        return value;
    }

    public BigInteger getInteger() {
        return new BigInteger(1, value);
    }

    public String getHexString() {
        return HexEncoder.getString(this.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.value);
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PrivateKey)) {
            return false;
        }
        final PrivateKey privateKey = ((PrivateKey) obj);
        return this.value.equals(privateKey.value);
    }

    public static PrivateKey random() {
        // TODO: 32 byte length PrivateKey is for Ed25519
        byte[] seed = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        return new PrivateKey(seed);
    }

    public static PrivateKey fromHexString(String hexString) {
        return new PrivateKey(new BigInteger(HexEncoder.getBytes(hexString)));
    }

    public static PrivateKey fromBytes(final byte[] bytes) {
        try {
            return new PrivateKey(bytes);
        } catch (final IllegalArgumentException e) {
            throw new CryptoException(e);
        }
    }

    public static PrivateKey fromBigInteger(BigInteger integer) {
        byte[] array = integer.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return new PrivateKey(array);
    }
}
