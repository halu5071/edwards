package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Coordinate;
import io.moatwel.crypto.eddsa.EncodedCoordinate;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EncodedCoordinateEd25519Test {

    @Test
    public void success_Decode_1() {
        EncodedCoordinate encoded = new EncodedCoordinateEd25519(HexEncoder.getBytes("762115b81aae8ab7a87e5d205ee64173ffc2666721b9bed118c4af49a2928601"));

        Coordinate coordinate = encoded.decode();

        assertThat(coordinate.getInteger(), is(new BigInteger("690082385501664621091624779109445751481919948714921317484605800924977635702")));
    }

    @Test
    public void success_Decode_2() {
        EncodedCoordinate encoded = new EncodedCoordinateEd25519(HexEncoder.getBytes("f29829ffdb3b229fd05dc7f83c1de7ab041cbbeb4156d7442f3e23de19c80701"));

        Coordinate coordinate = encoded.decode();

        assertThat(coordinate.getInteger(), is(new BigInteger("466061824698566712370651010976869652622695944005000025458774533499639142642")));
    }

    @Test
    public void success_Decode_3() {
        EncodedCoordinate encoded = new EncodedCoordinateEd25519(HexEncoder.getBytes("f193d7d58eb5ba3482c54b4dad4f9685726b2957cdf363fd4c6ed5a85e98750c"));

        Coordinate coordinate = encoded.decode();

        assertThat(coordinate.getInteger(), is(new BigInteger("5635526907038231869349643959556202269054548263441123979990494297630113764337")));
    }

    @Test
    public void success_Decode_4() {
        EncodedCoordinate encoded = new EncodedCoordinateEd25519(HexEncoder.getBytes("6e89e4b5973ab73a1538714746c77fd09f33aeeebdf11daffd94d6ba940ae108"));

        Coordinate coordinate = encoded.decode();

        assertThat(coordinate.getInteger(), is(new BigInteger("4016116405453202388474865418908325977025123430952466464539276325205466974574")));
    }

    @Test
    public void success_Decode_5() {
        EncodedCoordinate encoded = new EncodedCoordinateEd25519(HexEncoder.getBytes("df2780568c569c6713ed48bc7d96e04a93fdda45237bfc34afe40518b2635f02"));

        Coordinate coordinate = encoded.decode();

        assertThat(coordinate.getInteger(), is(new BigInteger("1073164242609237669094038971348660945523306704071742924708751717996060223455")));
    }
}
