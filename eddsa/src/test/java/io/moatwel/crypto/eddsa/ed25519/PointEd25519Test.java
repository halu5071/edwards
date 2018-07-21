package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(PowerMockRunner.class)
public class PointEd25519Test {

    private Curve curve = Ed25519Curve.getCurve();

    @Test
    public void success_AddPoint1() {
        Point point1 = new PointEd25519(new CoordinateEd25519(new BigInteger("10")), new CoordinateEd25519(new BigInteger("20")));
        Point point2 = new PointEd25519(new CoordinateEd25519(new BigInteger("20")), new CoordinateEd25519(new BigInteger("30")));

        Point result = point1.add(point2);

        assertThat(result.getX().getInteger(), is(new BigInteger("26779683712472377198728028204674893446113287909143558431051413280118073054006")));
        assertThat(result.getY().getInteger(), is(new BigInteger("10634460254639712273624836994541049759243301464550328073810114173764830681334")));
    }

    @Test
    public void success_AddPoint2() {
        Point point1 = new PointEd25519(new CoordinateEd25519(new BigInteger("141")), new CoordinateEd25519(new BigInteger("24")));
        Point point2 = new PointEd25519(new CoordinateEd25519(new BigInteger("23")), new CoordinateEd25519(new BigInteger("43")));

        Point result = point1.add(point2);

        assertThat(result.getX().getInteger(), is(new BigInteger("474593334618798863471616367945704120314864337702883208119694937456232892069")));
        assertThat(result.getY().getInteger(), is(new BigInteger("24906513834864817910919543317942654908387644989950283910758133364286718263050")));
    }

    @Test
    public void success_AddPoint3() {
        Point point1 = new PointEd25519(new CoordinateEd25519(new BigInteger("13411")), new CoordinateEd25519(new BigInteger("24312")));
        Point point2 = new PointEd25519(new CoordinateEd25519(new BigInteger("23423")), new CoordinateEd25519(new BigInteger("43423")));

        Point result = point1.add(point2);

        assertThat(result.getX().getInteger(), is(new BigInteger("36886960008504921885989612962868508923067925927973627109994183339251085321662")));
        assertThat(result.getY().getInteger(), is(new BigInteger("22676829173248331774615620100895385010848687053509896068625622483459677795547")));
    }

    @Test
    public void success_AddPoint4() {
        Point point1 = new PointEd25519(new CoordinateEd25519(new BigInteger("93481")), new CoordinateEd25519(new BigInteger("94823")));
        Point point2 = new PointEd25519(new CoordinateEd25519(new BigInteger("238534")), new CoordinateEd25519(new BigInteger("64234")));

        Point result = point1.add(point2);

        assertThat(result.getX().getInteger(), is(new BigInteger("31599891963011078369708610706029192869360807076143919676188064770774328631789")));
        assertThat(result.getY().getInteger(), is(new BigInteger("6333808798338954241148048118227044459247364198919264845931677861886349731634")));
    }

    @Test
    public void success_ScalarMultiply_1() {
        Point point = curve.getBasePoint();
        BigInteger integer = new BigInteger("1234");

        Point result = point.scalarMultiply(integer);

        assertThat(result.getX().getInteger(), is(new BigInteger("55556569241314067156494303609322045323771151550641480329783949256943018472903")));
        assertThat(result.getY().getInteger(), is(new BigInteger("32784530584814531279135473125766128158866185447326682367874410721387968224179")));
    }

    @Test
    public void success_AddBasePoint() {
        Point doubled = curve.getBasePoint().add(curve.getBasePoint());

        assertThat(doubled.getX().getInteger(), is(new BigInteger("24727413235106541002554574571675588834622768167397638456726423682521233608206")));
        assertThat(doubled.getY().getInteger(), is(new BigInteger("15549675580280190176352668710449542251549572066445060580507079593062643049417")));
    }

    @Test
    public void success_ScalarMultiplyBasePoint() {
        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("2"));

        assertThat(doubled.getX().getInteger(), is(new BigInteger("24727413235106541002554574571675588834622768167397638456726423682521233608206")));
        assertThat(doubled.getY().getInteger(), is(new BigInteger("15549675580280190176352668710449542251549572066445060580507079593062643049417")));
    }

    @Test
    public void success_ScalarMultiplyBasePoint_2() {
        Point scalard = curve.getBasePoint().scalarMultiply(new BigInteger("50459379271018302582465998844449622265826330103819895252966304478993432089656"));

        assertThat(scalard.getX().getInteger(), is(new BigInteger("15803359856018908320086002332714894013924030585248052893900291221487236226419")));
        assertThat(scalard.getY().getInteger(), is(new BigInteger("25416682171142283067951549518103646638934086440885266225724336361653813092611")));
    }

    @Test
    public void success_ClonePoint() {
        Point point = curve.getBasePoint();
        Point refCopy = point;
        Point valCopy = point.clone();

        assertEquals(point, refCopy);
        assertNotEquals(point, valCopy);
    }

    @Test
    public void success_EncodePoint_1() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
                new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));
    }

    @Test
    public void success_EncodePoint_2() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("11675954373387894284288004270057647646117187555908725144338394611307421402153")),
                new CoordinateEd25519(new BigInteger("6914948912687941235153802070429816612825513145320139793692760076939195789734")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("a631abbdf283aa8c79f23967935399e71d720eec6c4e90ccd57ae562eeb8498f"));
    }

    @Test
    public void success_EncodePoint_3() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("55307901837819056100203421472284281626339181044463972151446027320031681414103")),
                new CoordinateEd25519(new BigInteger("4592278534742875130003490239944802183338230954052483234431143871319686381534")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("deffe1a9ccc8ba06b10782013fbaa8154f4350e04e862151faac0cde3523278a"));
    }

    @Test
    public void success_EncodePoint_4() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("34533599460759434840195068027488100886792431177105624727278431380599494051297")),
                new CoordinateEd25519(new BigInteger("51422534855936905954058747336281739654670737325900075107235061596710295322677")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("354028754b43b4a27535a82375a7d4edefa90ced814e8a67ef543eb7911fb0f1"));
    }

    @Test
    public void success_EncodePoint_5() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660")),
                new CoordinateEd25519(new BigInteger("52873790972168047993308827189322012202737756658766965387349495052412272053380")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("840ce11e453af4c2e48fbec448b7de3957e167c16f8e72051c535dd75281e574"));
    }

    @Test
    public void success_EncodePoint_6() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("31621228259983782766387151846173419701451207683454700670358544852161525834558")),
                new CoordinateEd25519(new BigInteger("1087550498622212171315934886475455672530696511327350732598338573849547859723")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("0b67a11b2564accd38d9b963ac22eb64ed2ec9c17de25f7fe3209afc21886702"));
    }

    @Test
    public void success_EncodePoint_7() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")),
                new CoordinateEd25519(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("60d01f4c733a4e4f6890e67c8c62693e5c1dc7cadd68be5dfab0fe9f41011948"));
    }

    @Test
    public void success_EncodePoint_8() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("15859889424997121447678417203126552703333111509882764573373873495686990760265")),
                new CoordinateEd25519(new BigInteger("10096193892184502829137016296170451381135740053910753749871387609999636210212")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("24a2101437ae0680dc1425e0fc43ad7bbcfeec01ec4831b3907290d5443e5296"));
    }

    @Test
    public void success_EncodePoint_9() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
                new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));
    }

    @Test
    public void success_EncodePoint_10() {
        Point point = new PointEd25519(new CoordinateEd25519(new BigInteger("51129866767904606553230589361247885151272909473749371102570783512913896553871")),
                new CoordinateEd25519(new BigInteger("32605373213074853449054031639075642571848374710300664057820958199552138057137")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("b195102f70426e51c8e8ed0e31e74447e0b461a85e1ec14397bb88acbcfc15c8"));
    }
}
