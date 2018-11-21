package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;

public class PointEd448Test {

    private Curve curve = Curve448.getInstance();

    @Test
    public void success_AddPoint_1() {
        Point point1 = new PointEd448(
                new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385")),
                new CoordinateEd448(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521")));
        Point point2 = new PointEd448(
                new CoordinateEd448(new BigInteger("405639770870512859128695120627227803995321949712754759135967300223070531129746415370049997168133500416194521744365718523853001285570783")),
                new CoordinateEd448(new BigInteger("377227646310735357634648536724582072892370230695310953322949371452188035988425778909214764265487982345447623314077586021415261146220898")));

        Point result = point1.add(point2);

        assertThat(result.getX().getInteger(), is(new BigInteger("237307472488846393578005641401761614608199404627346808367605691704822363195287893433833964583862828740913530560298977830158905368505024")));
        assertThat(result.getY().getInteger(), is(new BigInteger("522625303705084068182188679361742093731050279111935572946670460212267444103355672712444629971590497597884758722953279019590401592768928")));
    }

    @Test
    public void success_AddPoint_2() {
        Point point1 = new PointEd448(
                new CoordinateEd448(new BigInteger("49729590024926883705949292896832095905118054184233662910554366985450733984769365837664107636334549191842981597231441932614315886910607")),
                new CoordinateEd448(new BigInteger("193741900868621819975499372099647484535272271429894036976062361471930494363363247663029822163982750251639381039128810944511255901134101")));
        Point point2 = new PointEd448(
                new CoordinateEd448(new BigInteger("62117243898733496688967557412042697612080350694727689659350063589509186232185918151981507824950746481782816546386254532592442795195570")),
                new CoordinateEd448(new BigInteger("310577999011408961223523636033077703506445675477877179880121843196090756145696550185689543851549850022388021022707914970612088814649187")));

        Point result = point1.add(point2);

        assertThat(result.getX().getInteger(), is(new BigInteger("176395691044101222624575770334854992369538691987358491952714454088259942347489360817372299090819361852205908722574473290760028715553204")));
        assertThat(result.getY().getInteger(), is(new BigInteger("402515361333166598716584847156550323043953894328794941096422403538273643810090110490706132383029213324986977371711771646865425102014449")));
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
    public void success_IsEqual_true_1() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("112345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_2() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("223456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_3() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("112345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_4() {
        Point point1 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = new PointEd448(new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("223456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_EncodePoint_1() {
        Point point = new PointEd448(
                new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385")),
                new CoordinateEd448(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("81d3a88178237b46386f73ab08fdd87bc35ec0d5390fb2545f71e78d16cae5a7e0a9089bff7d11187312fff5cd3eab84cfbc2f4a8917e7e480"));
    }

    @Test
    public void success_EncodePoint_2() {
        Point point = new PointEd448(
                new CoordinateEd448(new BigInteger("405639770870512859128695120627227803995321949712754759135967300223070531129746415370049997168133500416194521744365718523853001285570783")),
                new CoordinateEd448(new BigInteger("377227646310735357634648536724582072892370230695310953322949371452188035988425778909214764265487982345447623314077586021415261146220898")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("62896cfce155824cae979e18533d5dc91d80bdbfe541d7ab49a790e2d0579accd810de8da509bc519c47f30363f7e7507733db26fb08dd8480"));
    }
}
