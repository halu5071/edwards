package io.moatwel.crypto.eddsa.ed448;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.PrivateKey;
import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class PointEd448Test {

    private Curve curve = Curve448.getInstance();

    @Test
    public void success_AddPoint_1() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385")),
                new CoordinateEd448(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521")));
        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("405639770870512859128695120627227803995321949712754759135967300223070531129746415370049997168133500416194521744365718523853001285570783")),
                new CoordinateEd448(new BigInteger("377227646310735357634648536724582072892370230695310953322949371452188035988425778909214764265487982345447623314077586021415261146220898")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("237307472488846393578005641401761614608199404627346808367605691704822363195287893433833964583862828740913530560298977830158905368505024")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("522625303705084068182188679361742093731050279111935572946670460212267444103355672712444629971590497597884758722953279019590401592768928")));
    }

    @Test
    public void success_AddPoint_2() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("49729590024926883705949292896832095905118054184233662910554366985450733984769365837664107636334549191842981597231441932614315886910607")),
                new CoordinateEd448(new BigInteger("193741900868621819975499372099647484535272271429894036976062361471930494363363247663029822163982750251639381039128810944511255901134101")));
        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("62117243898733496688967557412042697612080350694727689659350063589509186232185918151981507824950746481782816546386254532592442795195570")),
                new CoordinateEd448(new BigInteger("310577999011408961223523636033077703506445675477877179880121843196090756145696550185689543851549850022388021022707914970612088814649187")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("176395691044101222624575770334854992369538691987358491952714454088259942347489360817372299090819361852205908722574473290760028715553204")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("402515361333166598716584847156550323043953894328794941096422403538273643810090110490706132383029213324986977371711771646865425102014449")));
    }

    @Test
    public void success_AddPoint_Origin() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("49729590024926883705949292896832095905118054184233662910554366985450733984769365837664107636334549191842981597231441932614315886910607")),
                new CoordinateEd448(new BigInteger("193741900868621819975499372099647484535272271429894036976062361471930494363363247663029822163982750251639381039128810944511255901134101")));

        Point result = point1.add(PointEd448.O);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("49729590024926883705949292896832095905118054184233662910554366985450733984769365837664107636334549191842981597231441932614315886910607")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("193741900868621819975499372099647484535272271429894036976062361471930494363363247663029822163982750251639381039128810944511255901134101")));
    }

    @Test
    public void success_ScalarMultiplePoint_ZERO() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("49729590024926883705949292896832095905118054184233662910554366985450733984769365837664107636334549191842981597231441932614315886910607")),
                new CoordinateEd448(new BigInteger("193741900868621819975499372099647484535272271429894036976062361471930494363363247663029822163982750251639381039128810944511255901134101")));

        Point result = point1.scalarMultiply(BigInteger.ZERO);

        assertThat(result.getAffineX().getInteger(), is(BigInteger.ZERO));
        assertThat(result.getAffineY().getInteger(), is(BigInteger.ONE));
    }

    @Test
    public void success_ScalarMultipleBasePoint_2() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("2"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("484559149530404593699549205258669689569094240458212040187660132787056912146709081364401144455726350866276831544947397859048262938744149")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("494088759867433727674302672526735089350544552303727723746126484473087719117037293890093462157703888342865036477787453078312060500281069")));
    }

    @Test
    public void success_ScalarMultipleBasePoint_3() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("3"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("23839778817283171003887799738662344287085130522697782688245073320169861206004018274567429238677677920280078599146891901463786155880335")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("636046652612779686502873775776967954190574036985351036782021535703553242737829645273154208057988851307101009474686328623630835377952508")));
    }

    @Test
    public void success_ScalarMultipleBasePoint_7() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("7"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("21552347002471831326081673315959198890815298992330888454662334499946296341989387947872761885158213982937463940347052051774843037018871")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("357373306191655299280537582309534138704679428048844536962096044990522311544407707633625075281628144531544209749465261583401063761590143")));
    }

    @Test
    public void success_ScalarMultipleBasePoint_8() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("8"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("596076689965651660022516817574257859767655189303710608336194617254375604050911414190272256792693764900933801964043657940361520281271776")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("565960773781129488052659607211963370179410097582298438377162450965951398045899014271088170591759362241006993622586109875821902761156763")));
    }

    @Test
    public void success_ScalarMultipleBasePoint_9() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("9"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("678819586033147925281023223806960408804378601126531157763570688900376738103095651143762799384400423222857151421219751020550555632887915")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("60696086077381741094032748984832537947444053808169978921575679174195124930944594569279421079811560196531757705827406107516052224374095")));
    }

    @Test
    public void success_ScalarMultipleBasePoint_10() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("10"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("338669802554017338090741842335737823113336653904160109397584018105059385206196637853257117971041875208554805602850382915119972512247869")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("219150861381236143450521108354203769270679720218000652369136137699333671138749674479139795638088562049448210382871218396511167516106599")));
    }

    @Test
    public void success_ScalarMultipleBasePoint_47218412417289471() {
        Point point = curve.getBasePoint().scalarMultiply(new BigInteger("47218412417289471"));

        assertThat(point.getAffineX().getInteger(), is(new BigInteger("706962928758557286146477331671104898387376109527551747178149994986356021591923299562304281357717856573928016518683667087189558043425510")));
        assertThat(point.getAffineY().getInteger(), is(new BigInteger("279992018783083106764723692021891527281730215435161171351137438665373473663265784536951370748332118946047677007832925697871713328581900")));
    }

    @Test
    public void success_IsEqual_true_1() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("112345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_2() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("223456")));

        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_3() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("112345")),
                new CoordinateEd448(new BigInteger("23456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_4() {
        Point point1 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("23456")));

        Point point2 = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("12345")),
                new CoordinateEd448(new BigInteger("223456")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_EncodePoint_1() {
        Point point = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("34739492400859860395182678144950001130156618760165224345037275968255527647563316333838132457128768990740201158779360426801230269378385")),
                new CoordinateEd448(new BigInteger("649903705284910193856318595038125557166018654435367923522702114760308296858957956415522408311508190563055939943858476798475601957147521")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("81d3a88178237b46386f73ab08fdd87bc35ec0d5390fb2545f71e78d16cae5a7e0a9089bff7d11187312fff5cd3eab84cfbc2f4a8917e7e480"));
    }

    @Test
    public void success_EncodePoint_2() {
        Point point = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("405639770870512859128695120627227803995321949712754759135967300223070531129746415370049997168133500416194521744365718523853001285570783")),
                new CoordinateEd448(new BigInteger("377227646310735357634648536724582072892370230695310953322949371452188035988425778909214764265487982345447623314077586021415261146220898")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("62896cfce155824cae979e18533d5dc91d80bdbfe541d7ab49a790e2d0579accd810de8da509bc519c47f30363f7e7507733db26fb08dd8480"));
    }

    @Test
    public void success_EncodePoint_3() {
        Point point = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("434391662203765465823249281555158189156164810379534328666332058600963815324581635652355097867679375909658325678726006286860027155260225")),
                new CoordinateEd448(new BigInteger("184191899734212422533061996231693581823187306139483639312412621133237619000236941162604728922939245175108770212359093165553006932613943")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("375b6b4fc8e95b69eeeb91cdc9aadb7434a10607c05ea17e8c7836def6add15b4c21c03b42f1904da394daae84ab33c376bb38f6adcfdf4080"));
    }

    @Test
    public void success_EncodePoint_4() {
        Point point = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("125289221583267818863767698397223457910113042178416735810899566843187314223588591086597413086534600862177622477005418944936222198777153")),
                new CoordinateEd448(new BigInteger("648448382792176285482204165479965312989436144273325155639830462878317617886722481714303636303151921421401113199085535186523230837992427")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("ebeb9070141b17b932776fc108b38dbfadcb116797e0a684c94e5be42630d709e9f30e13f9fd33d6cc5759739ded71a9c3c401f521df63e480"));
    }

    @Test
    public void success_EncodePoint_5() {
        Point point = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("22707985587331256868589771723008988245115849649655333990667320929228129410125712160297039615600506068903416644473874336310758778361942")),
                new CoordinateEd448(new BigInteger("496676156496560221629674811271269816108141642439975403617451714432775542969132094081254666654186683180292879981700393245342697802041574")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("e608be815e330bcc1e6f5dc4b1212313eb67a24cb2604fa7a0f699f697800cf0b3923563e01bbe42261b4c68bf60e0cec061cd0dd534efae00"));
    }

    @Test
    public void success_EncodePoint_6() {
        Point point = PointEd448.fromAffine(
                new CoordinateEd448(new BigInteger("225756383469361994764865051983871508178099949800497695499931707392687883349530454451287466079125470038968641752626737669127046516344041")),
                new CoordinateEd448(new BigInteger("164642323710136210205802282154206391535679777613806891561058890791910414360903683520045572694907798135197993891247717192774546867305043")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length_1() {
        PrivateKeyEd448.fromBytes(new byte[58]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GeneratePrivateKey_wrong_byte_length_2() {
        PrivateKeyEd448.fromBytes(new byte[56]);
    }

    @Test
    public void success_GeneratePrivateKey_random() {
        PrivateKey key = PrivateKeyEd448.random();
        assertNotNull(key);
        assertThat(key.getRaw().length, is(57));
    }

//    @Test(expected = IllegalComparisonException.class)
//    public void failure_IsEqual_other_scheme_point() {
//        Point point1 = PointEd25519TestFactory.getOriginPoint();
//        Point point2 = PointEd448TestFactory.getOriginPoint();
//
//        point1.isEqual(point2);
//    }
}
