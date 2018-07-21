package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;

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
}
