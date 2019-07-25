package io.moatwel.crypto.eddsa.ed25519;

import org.junit.Test;

import java.math.BigInteger;

import io.moatwel.crypto.eddsa.Curve;
import io.moatwel.crypto.eddsa.IllegalComparisonException;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.crypto.eddsa.ed448.PointEd448TestFactory;
import io.moatwel.util.HexEncoder;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class PointEd25519Test {

    private Curve curve = Curve25519.getInstance();

    @Test
    public void success_AddPoint1() {
        Point point1 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("10")), new CoordinateEd25519(new BigInteger("20")));
        Point point2 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("20")), new CoordinateEd25519(new BigInteger("30")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("26779683712472377198728028204674893446113287909143558431051413280118073054006")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("10634460254639712273624836994541049759243301464550328073810114173764830681334")));
    }

    @Test
    public void success_AddPoint2() {
        Point point1 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("141")), new CoordinateEd25519(new BigInteger("24")));
        Point point2 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("23")), new CoordinateEd25519(new BigInteger("43")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("474593334618798863471616367945704120314864337702883208119694937456232892069")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("24906513834864817910919543317942654908387644989950283910758133364286718263050")));
    }


    @Test
    public void success_AddPoint3() {
        Point point1 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("13411")), new CoordinateEd25519(new BigInteger("24312")));
        Point point2 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("23423")), new CoordinateEd25519(new BigInteger("43423")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("36886960008504921885989612962868508923067925927973627109994183339251085321662")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("22676829173248331774615620100895385010848687053509896068625622483459677795547")));
    }

    @Test
    public void success_AddPoint4() {
        Point point1 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("93481")), new CoordinateEd25519(new BigInteger("94823")));
        Point point2 = PointEd25519.fromAffine(new CoordinateEd25519(new BigInteger("238534")), new CoordinateEd25519(new BigInteger("64234")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("31599891963011078369708610706029192869360807076143919676188064770774328631789")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("6333808798338954241148048118227044459247364198919264845931677861886349731634")));
    }

    @Test
    public void success_AddPoint5() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
                new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));
        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("11675954373387894284288004270057647646117187555908725144338394611307421402153")),
                new CoordinateEd25519(new BigInteger("6914948912687941235153802070429816612825513145320139793692760076939195789734")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("48503653771611185505641550378000927615234160991025034313672702576429802482305")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("55906285724051886338008287911122855934156241601415494231223064909912279321827")));
    }

    @Test
    public void success_AddPoint6() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("55307901837819056100203421472284281626339181044463972151446027320031681414103")),
                new CoordinateEd25519(new BigInteger("4592278534742875130003490239944802183338230954052483234431143871319686381534")));
        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
                new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("13822711300349466982677984643260416445346651573002956528288968112843725329775")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("49357477884335216030914773679750452456619347178750051140322405303989353243151")));
    }

    @Test
    public void success_AddPoint7() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("34533599460759434840195068027488100886792431177105624727278431380599494051297")),
                new CoordinateEd25519(new BigInteger("51422534855936905954058747336281739654670737325900075107235061596710295322677")));
        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("55307901837819056100203421472284281626339181044463972151446027320031681414103")),
                new CoordinateEd25519(new BigInteger("4592278534742875130003490239944802183338230954052483234431143871319686381534")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("34000649668223248488254401591736403979321217591392207588742642580926190319364")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("17558251693341875201664128833815398118983031625840378408984148054333403861042")));
    }

    @Test
    public void success_AddPoint8() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660")),
                new CoordinateEd25519(new BigInteger("52873790972168047993308827189322012202737756658766965387349495052412272053380")));
        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("34533599460759434840195068027488100886792431177105624727278431380599494051297")),
                new CoordinateEd25519(new BigInteger("51422534855936905954058747336281739654670737325900075107235061596710295322677")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("20245698879030783691519219675334277708739244551573616706757188813638472517317")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("11927906694103038927593975893798604203875081450043718939350407976683327255477")));
    }

    @Test
    public void success_AddPoint9() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("31621228259983782766387151846173419701451207683454700670358544852161525834558")),
                new CoordinateEd25519(new BigInteger("1087550498622212171315934886475455672530696511327350732598338573849547859723")));
        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660")),
                new CoordinateEd25519(new BigInteger("52873790972168047993308827189322012202737756658766965387349495052412272053380")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("10231238983259957665520424972260773583563625054906107477931951171166394182461")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("16175802527788616834701228315101703266962390276165245252584971134833495651114")));
    }

    @Test
    public void success_AddPoint10() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")),
                new CoordinateEd25519(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));
        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("31621228259983782766387151846173419701451207683454700670358544852161525834558")),
                new CoordinateEd25519(new BigInteger("1087550498622212171315934886475455672530696511327350732598338573849547859723")));

        Point result = point1.add(point2);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("35609955356486491496360028406142810435910830517694536589708456029301666527874")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("33972043234789475673904984064588138758737764726163691391551272801822821209432")));
    }

    @Test
    public void success_AddPoint_Origin() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")),
                new CoordinateEd25519(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));

        Point result = point1.add(PointEd25519.O);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));
    }

    @Test
    public void success_DoublePoint1() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")),
                new CoordinateEd25519(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));

        Point result = point1.doubling();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("5987863445047604323332331916419599613324592255845398311770416099113334424608")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("39861087583445426187551354580036325574649759698571028202521637397851278215411")));
    }

    @Test
    public void success_DoublePoint2() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
                new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));

        Point result = point1.doubling();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("22836960031408748183243516943200517344577381793151670589055500773034201890053")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("23804117792551319444690172290830645910275025135641944382002990267771946471382")));
    }

    @Test
    public void success_DoublePoint3() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("55307901837819056100203421472284281626339181044463972151446027320031681414103")),
                new CoordinateEd25519(new BigInteger("4592278534742875130003490239944802183338230954052483234431143871319686381534")));

        Point result = point1.doubling();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("28626000581693394141050330053890414343188269600220079815398353814232273344195")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("40088742308296800703381227754515309370051965153412279321897451990712491547584")));
    }

    @Test
    public void success_DoublePoint4() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("34533599460759434840195068027488100886792431177105624727278431380599494051297")),
                new CoordinateEd25519(new BigInteger("51422534855936905954058747336281739654670737325900075107235061596710295322677")));

        Point result = point1.doubling();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("26863303488338137487738944045950290130494361050415662162100060472554915039731")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("40761782721757697465769263092900138179392988686301162293668714786554317846098")));
    }

    @Test
    public void success_DoublePoint5() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660")),
                new CoordinateEd25519(new BigInteger("52873790972168047993308827189322012202737756658766965387349495052412272053380")));

        Point result = point1.doubling();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("30718866013704992179195177686906320997707889915211887199835746036506855504210")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("31042941307969375649951409902056903858841149703631519666496715611854428631549")));
    }

    @Test
    public void success_DoublePoint6() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("31621228259983782766387151846173419701451207683454700670358544852161525834558")),
                new CoordinateEd25519(new BigInteger("1087550498622212171315934886475455672530696511327350732598338573849547859723")));

        Point result = point1.doubling();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("54335164024625743934669286787931302569680669857893696519224744689691858515668")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("44807246093863216660634594959379875777640228908622772878292058541219108796161")));
    }

    @Test
    public void success_negateY() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")),
                new CoordinateEd25519(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));

        Point result = point1.negateY();

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("25285339673051149677950892762890234916468860261702545400327866269283454562189")));
    }

    @Test
    public void success_ScalarMultiply_1() {
        Point point = curve.getBasePoint();
        BigInteger integer = new BigInteger("1234");

        Point result = point.scalarMultiply(integer);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("55556569241314067156494303609322045323771151550641480329783949256943018472903")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("32784530584814531279135473125766128158866185447326682367874410721387968224179")));
    }

    @Test
    public void success_ScalarMultiply_2() {
        Point point = curve.getBasePoint();
        BigInteger integer = new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831");

        Point result = point.scalarMultiply(integer);

        assertThat(result.getAffineX().getInteger(), is(new BigInteger("36568395279531091001405240627702774400329345357946000277861114291457062189012")));
        assertThat(result.getAffineY().getInteger(), is(new BigInteger("6892543919216139430465404745243127488161491607535545431263766463424432810420")));
    }

    //
//    @Test
//    public void success_ScalarMultiply_3() {
//        Point point = curve.getBasePoint();
//        BigInteger integer = new BigInteger("11675954373387894284288004270057647646117187555908725144338394611307421402153");
//
//        Point result = point.scalarMultiply(integer);
//
//        assertThat(result.getX().getInteger(), is(new BigInteger("2550105584539864958223359997109982244652817874690374654323009420113342284222")));
//        assertThat(result.getY().getInteger(), is(new BigInteger("32100423734119761214020102691557112218747037854384677234614616607240732191696")));
//    }
//
//    @Test
//    public void success_ScalarMultiply_4() {
//        Point point = curve.getBasePoint();
//        BigInteger integer = new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660");
//
//        Point result = point.scalarMultiply(integer);
//
//        assertThat(result.getX().getInteger(), is(new BigInteger("55567266549953732748489637086272210307507483701392087766383203587162091263037")));
//        assertThat(result.getY().getInteger(), is(new BigInteger("39648261582079248220577879738713959882783855750578332978656472445048155089907")));
//    }
//
//    @Test
//    public void success_ScalarMultiply_5() {
//        Point point = curve.getBasePoint();
//        BigInteger integer = new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760");
//
//        Point result = point.scalarMultiply(integer);
//
//        assertThat(result.getX().getInteger(), is(new BigInteger("46453596183992846648371334773013814104200062737923250995844281103986991912429")));
//        assertThat(result.getY().getInteger(), is(new BigInteger("25430834724210084628427024029388177706947140598135008372913684687859787885119")));
//    }
//
    @Test
    public void success_ScalarMultiply_6() {
        Point point = curve.getBasePoint();

        Point result = point.scalarMultiply(BigInteger.ZERO);

        assertThat(result.getX().getInteger(), is(BigInteger.ZERO));
        assertThat(result.getY().getInteger(), is(BigInteger.ONE));
    }

    @Test
    public void success_AddBasePoint() {
        Point doubled = curve.getBasePoint().add(curve.getBasePoint());

        assertThat(doubled.getAffineX().getInteger(), is(new BigInteger("24727413235106541002554574571675588834622768167397638456726423682521233608206")));
        assertThat(doubled.getAffineY().getInteger(), is(new BigInteger("15549675580280190176352668710449542251549572066445060580507079593062643049417")));
    }

    @Test
    public void success_ScalarMultiplyBasePoint_2() {
        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("2"));

        assertThat(doubled.getAffineX().getInteger(), is(new BigInteger("24727413235106541002554574571675588834622768167397638456726423682521233608206")));
        assertThat(doubled.getAffineY().getInteger(), is(new BigInteger("15549675580280190176352668710449542251549572066445060580507079593062643049417")));
    }

    //
//    @Test
//    public void success_ScalarMultiplyBasePoint_7() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("7"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("9199134265559022971505535402808359556995554859516252602543778295037484220679")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("22512087849695599276028560866629687720820254811233262850576678203618951717560")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_3() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("3"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("46896733464454938657123544595386787789046198280132665686241321779790909858396")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("8324843778533443976490377120369201138301417226297555316741202210403726505172")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_4() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("4"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("14582954232372986451776170844943001818709880559417862259286374126315108956272")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("32483318716863467900234833297694612235682047836132991208333042722294373421359")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_6() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("6"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("34643617590234865996699167120328052565261792237873803846102513686264813449789")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("2399184961499513294557607325187831088545696902880432827228757905043131825908")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_10() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("10"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("43500613248243327786121022071801015118933854441360174117148262713429272820047")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("45005105423099817237495816771148012388779685712352441364231470781391834741548")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_11() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("11"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("9451145793506787353375160377761530931587019091193333050860601958827395183563")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("20609402718286069808115703540855311742885093522056241285814584245966805874451")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_12() {
//        Point doubled = curve.getBasePoint().scalarMultiply(new BigInteger("12"));
//
//        assertThat(doubled.getX().getInteger(), is(new BigInteger("32159939716063394567822525359727347405356413309540137282993608327129696604205")));
//        assertThat(doubled.getY().getInteger(), is(new BigInteger("29147333543209904737197244325450674102993621692520459538942544703173373584633")));
//    }
//
//    @Test
//    public void success_ScalarMultiplyBasePoint_50459379271018302582465998844449622265826330103819895252966304478993432089656() {
//        Point scalard = curve.getBasePoint().scalarMultiply(new BigInteger("50459379271018302582465998844449622265826330103819895252966304478993432089656"));
//
//        assertThat(scalard.getX().getInteger(), is(new BigInteger("15803359856018908320086002332714894013924030585248052893900291221487236226419")));
//        assertThat(scalard.getY().getInteger(), is(new BigInteger("25416682171142283067951549518103646638934086440885266225724336361653813092611")));
//    }
//
//    @Test
//    public void success_MultiOperation_1() {
//        BigInteger k = new BigInteger("6075980004175535879679826160500264550302046044703001554511768035174960884068121242792397217197363038097667151841372253838835089167259419742248753963346391");
//        BigInteger r = new BigInteger("7368313437276165600538158652835868406847530051071893351052927312315159593412414852560947822723289365893543058291013782043548190862352985926994804682235672");
//        BigInteger s = new BigInteger("45574626401593346369382133240842874906163693510868742802398980918235613620592");
//
//        BigInteger result = k.mod(curve.getPrimeL()).multiply(s).add(r).mod(curve.getPrimeL());
//
//        assertThat(result, is(new BigInteger("319146615599574595135908926944340520491598694492366832960461172005503422390")));
//    }
//
    @Test
    public void success_EncodePoint_1() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")),
                new CoordinateEd25519(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));
    }

    @Test
    public void success_EncodePoint_2() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("11675954373387894284288004270057647646117187555908725144338394611307421402153")),
                new CoordinateEd25519(new BigInteger("6914948912687941235153802070429816612825513145320139793692760076939195789734")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("a631abbdf283aa8c79f23967935399e71d720eec6c4e90ccd57ae562eeb8498f"));
    }

    @Test
    public void success_EncodePoint_3() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("55307901837819056100203421472284281626339181044463972151446027320031681414103")),
                new CoordinateEd25519(new BigInteger("4592278534742875130003490239944802183338230954052483234431143871319686381534")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("deffe1a9ccc8ba06b10782013fbaa8154f4350e04e862151faac0cde3523278a"));
    }

    @Test
    public void success_EncodePoint_4() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("34533599460759434840195068027488100886792431177105624727278431380599494051297")),
                new CoordinateEd25519(new BigInteger("51422534855936905954058747336281739654670737325900075107235061596710295322677")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("354028754b43b4a27535a82375a7d4edefa90ced814e8a67ef543eb7911fb0f1"));
    }

    @Test
    public void success_EncodePoint_5() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660")),
                new CoordinateEd25519(new BigInteger("52873790972168047993308827189322012202737756658766965387349495052412272053380")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("840ce11e453af4c2e48fbec448b7de3957e167c16f8e72051c535dd75281e574"));
    }

    @Test
    public void success_EncodePoint_6() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("31621228259983782766387151846173419701451207683454700670358544852161525834558")),
                new CoordinateEd25519(new BigInteger("1087550498622212171315934886475455672530696511327350732598338573849547859723")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("0b67a11b2564accd38d9b963ac22eb64ed2ec9c17de25f7fe3209afc21886702"));
    }

    @Test
    public void success_EncodePoint_7() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")),
                new CoordinateEd25519(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("60d01f4c733a4e4f6890e67c8c62693e5c1dc7cadd68be5dfab0fe9f41011948"));
    }

    @Test
    public void success_EncodePoint_8() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("15859889424997121447678417203126552703333111509882764573373873495686990760265")),
                new CoordinateEd25519(new BigInteger("10096193892184502829137016296170451381135740053910753749871387609999636210212")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("24a2101437ae0680dc1425e0fc43ad7bbcfeec01ec4831b3907290d5443e5296"));
    }

    @Test
    public void success_EncodePoint_9() {
        BigInteger x = new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831");
        BigInteger y = new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982");
        Point point = PointEd25519.fromAffine(new CoordinateEd25519(x), new CoordinateEd25519(y));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));
    }

    @Test
    public void success_EncodePoint_10() {
        BigInteger x = new BigInteger("51129866767904606553230589361247885151272909473749371102570783512913896553871");
        BigInteger y = new BigInteger("32605373213074853449054031639075642571848374710300664057820958199552138057137");
        Point point = PointEd25519.fromAffine(new CoordinateEd25519(x), new CoordinateEd25519(y));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("b195102f70426e51c8e8ed0e31e74447e0b461a85e1ec14397bb88acbcfc15c8"));
    }

    @Test
    public void success_EncodePoint_11() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("13267040035417295396187264812269447027004279287377164120608901297558640265393")),
                new CoordinateEd25519(new BigInteger("30659936914619338944546583179452063721257503761316379129960678675145268230154")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("0a7839c8658c2186c5650644ee832c092cb46bff7c6a777621567dd5c9e8c8c3"));
    }

    @Test
    public void success_EncodePoint_12() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("50505920206304101148506670769962044834562415690945180860800334635063441812972")),
                new CoordinateEd25519(new BigInteger("52893620576450359719018512374896078131701031161676122303582965125535080500247")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("17ccd9301c1504aa65aed4872634d7317707fd8e95bbc3b4c4e732be73baf074"));
    }

    @Test
    public void success_EncodePoint_13() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("5288904915125359943317363554591172762473106809525857286939154287576903061215")),
                new CoordinateEd25519(new BigInteger("49583116013539038265297505995597360672194268243619584093840920874690478834199")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("1782e3085548baead1ac7ab9befa1259f892e59102ac7022506e6de0940c9fed"));
    }

    @Test
    public void success_EncodePoint_14() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("27443345399801550503820810706683867803355265925449420625371997396755160603300")),
                new CoordinateEd25519(new BigInteger("2564001854993589394597821165299375341350553971038818461341845310541327703804")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("fc1e0fede6e4549180dcdb91a629ea9d30fb9ab61da5f789726d5882722cab05"));
    }

    @Test
    public void success_EncodePoint_15() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("26579811288929527007271986534949559889238357380924397736032152196006905219455")),
                new CoordinateEd25519(new BigInteger("32830504693991902250379781095167938240398939587214709772415373618962111188227")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("03cd98b81ef433956b7e2b239910450605959361e6391ebb770149693b6895c8"));
    }

    @Test
    public void success_EncodePoint_16() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("42949322561463186230299817970593613279310279966655824621762638884512104730735")),
                new CoordinateEd25519(new BigInteger("34290536749966261157057464511838359353942848384132466399369493876322787415148")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("6c543c13177252112541e3382e5b73be26a5360e68459c87604ac53b8ac1cfcb"));
    }

    @Test
    public void success_EncodePoint_17() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("16119696165958767068520039407917355163375427197667342664755069949040746442291")),
                new CoordinateEd25519(new BigInteger("11382165760643794875560273637359185509760076262240039946799577435076376239241")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("899c9d230f24d416647b0cfa04edc8158bb87bcd4332901cda27a979d8132a99"));
    }

    @Test
    public void success_EncodePoint_18() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("28991574176798270631055516789513246251336837817295903512076991779188778127680")),
                new CoordinateEd25519(new BigInteger("43109591168687823035564402387271177577811433066020507559569157621096510013345")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("a13f3a02cc97ec252b785702ce5f1a201a0fc7dd177c636c5f97482af7294f5f"));
    }

    @Test
    public void success_EncodePoint_19() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("47481641482705931103934862287125658686534006637492775092431200862455707981015")),
                new CoordinateEd25519(new BigInteger("55756317091645948491064284809040306721406210822346482531807933600495972956139")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("ebb7b4086e62dfd02dc01ab9c5c05828beb0756207aafd74a9ffc9f506f544fb"));
    }

    @Test
    public void success_EncodePoint_20() {
        Point point = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        byte[] result = point.encode().getValue();

        assertThat(HexEncoder.getString(result), is("1c8dc594082e7ddad6a97f500247a585993d3b1a797041ce6f203902a7816833"));
    }

    @Test
    public void success_IsEqual_true_1() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        assertThat(point1.isEqual(point2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("55756317091645948491064284809040306721406210822346482531807933600495972956139")));

        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_2() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("47481641482705931103934862287125658686534006637492775092431200862455707981015")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_3() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("55756317091645948491064284809040306721406210822346482531807933600495972956139")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test
    public void success_IsEqual_false_4() {
        Point point1 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        Point point2 = PointEd25519.fromAffine(
                new CoordinateEd25519(new BigInteger("47481641482705931103934862287125658686534006637492775092431200862455707981015")),
                new CoordinateEd25519(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));

        assertThat(point1.isEqual(point2), is(false));
    }

    @Test(expected = IllegalComparisonException.class)
    public void failure_IsEqual_other_scheme_point() {
        Point point1 = PointEd25519TestFactory.getOriginPoint();
        Point point2 = PointEd448TestFactory.getOriginPoint();

        point1.isEqual(point2);
    }
}
