package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.DecodeException;
import io.moatwel.crypto.eddsa.EncodedPoint;
import io.moatwel.crypto.eddsa.Point;
import io.moatwel.util.HexEncoder;
import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EncodedPointEd448Test {

    @Test
    public void success_DecodePoint_1() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("fe73d757bbbc3754bc121a8e541013daab78f022af8a0391ea7413c11d317821038039890768fd93f6a1850c4ce2948a02c5278ff1dfd21a80"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("346711535767036312264896787009588144353847535648881470250016240193210663703211967520979531621448938121538315092227252553492140171084741")));
        assertThat(point.getY().getInteger(), is(new BigInteger("76158302379442260505276576686796488278997776206127607371674860847167404089902911584147334234478926201420191503410874437273677905490942")));
    }

    @Test
    public void success_DecodePoint_2() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("0f2b395332546de9d1660f655ab55abeefbe51ac741c402e54a5f917bbaf36c0962a0271b171ba45b926bf90dbdbcd9f2ff9dbb00dee399a00"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("473448419713252858677303287009520914550496204589330385196771477480559446433327840275990830355028542607289358478770368502892836706131924")));
        assertThat(point.getY().getInteger(), is(new BigInteger("437881401956668718546626044399132348443052768806271829566570270792308122922154847082300261037201681480880236494147873849823734546377487")));
    }

    @Test
    public void success_DecodePoint_3() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("c6c5ee5bbd1a6abf49ed522ecfdce18f66c8872a9c4c3c3061292a6f7020179a7de0089f15c275ec14e01180c0dbe41732200a7628fe5f7000"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("472067484368213515937816390739321044164758042133140508836395663489652332002738245695993700980622152470363675557312182877688850671564164")));
        assertThat(point.getY().getInteger(), is(new BigInteger("319056567243186338229131462709903384480410384317025731854394641070448863807652348269431018082259219462543405812580172294129861864113606")));
    }

    @Test
    public void success_DecodePoint_4() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("375b6b4fc8e95b69eeeb91cdc9aadb7434a10607c05ea17e8c7836def6add15b4c21c03b42f1904da394daae84ab33c376bb38f6adcfdf4080"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("434391662203765465823249281555158189156164810379534328666332058600963815324581635652355097867679375909658325678726006286860027155260225")));
        assertThat(point.getY().getInteger(), is(new BigInteger("184191899734212422533061996231693581823187306139483639312412621133237619000236941162604728922939245175108770212359093165553006932613943")));
    }

    @Test
    public void success_DecodePoint_5() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("e608be815e330bcc1e6f5dc4b1212313eb67a24cb2604fa7a0f699f697800cf0b3923563e01bbe42261b4c68bf60e0cec061cd0dd534efae00"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("22707985587331256868589771723008988245115849649655333990667320929228129410125712160297039615600506068903416644473874336310758778361942")));
        assertThat(point.getY().getInteger(), is(new BigInteger("496676156496560221629674811271269816108141642439975403617451714432775542969132094081254666654186683180292879981700393245342697802041574")));
    }

    @Test
    public void success_DecodePoint_6() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("cc8c0190b54ff5b661a488a32228ef349088240f23bb1753be89009ab79d7062bc4fbec9c6d6d1f483fcaaf9031ce9ec568f182e973bcd2e00"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("480807133313964796499400988056627091574898085379655935798780429688299075972928435310433131611536740705714563718923737373165478812152020")));
        assertThat(point.getY().getInteger(), is(new BigInteger("132880004060171722927589204279587192827090013151273721438143079295786882790456824968399727312748599897535872744433752084709899382131916")));
    }

    @Test
    public void success_DecodePoint_7() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("46defb9707811318881b825cd8a0741d448834df6c2605984b904eec07e50ffa9aaf87b71d31bd642512f3ac64b9638978b5019d971a042a00"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("563417256270594863614723441012793115381602779692542652989705882162736975994766797051100826972905956297979977372086433892499398237563796")));
        assertThat(point.getY().getInteger(), is(new BigInteger("119292492974486904486081400066271249791300114802505381539357901845907231099416375866897143621432461773288811121724501855677372190940742")));
    }

    @Test
    public void success_DecodePoint_8() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("375b6b4fc8e95b69eeeb91cdc9aadb7434a10607c05ea17e8c7836def6add15b4c21c03b42f1904da394daae84ab33c376bb38f6adcfdf4080"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("434391662203765465823249281555158189156164810379534328666332058600963815324581635652355097867679375909658325678726006286860027155260225")));
        assertThat(point.getY().getInteger(), is(new BigInteger("184191899734212422533061996231693581823187306139483639312412621133237619000236941162604728922939245175108770212359093165553006932613943")));
    }

    @Test
    public void success_DecodePoint_9() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("e74fd58140a597731795be66eaec1e063d256832dbcea6dfe21adc8041ae8b31a9588b13f9b2f2232eace315fc74b780aee7c89d3adf73a900"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("301691883603492836727079090960851537496073990437822845364158598665131520995120737122432395009099571965094362989107989663302776640354658")));
        assertThat(point.getY().getInteger(), is(new BigInteger("481112225585696362014980878625362306168838475545308139490948103572919911491515962060412308047260747410592200786904559655653791457693671")));
    }

    @Test
    public void success_DecodePoint_10() throws DecodeException {
        EncodedPoint encodedPoint = new EncodedPointEd448(HexEncoder.getBytes("fc0c43838ea49d80316e3d1a637e99dc7adc3fea0c5c7852798ba6d2385b0c66044462f1913cfb34abdc3fb6d1c1039c5e1b451827534ea380"));

        Point point = encodedPoint.decode();

        assertThat(point.getX().getInteger(), is(new BigInteger("449601228056392842230918689215266494656853731174814964546460532894095209940282727350955807386237790569082667715328043268032774236716391")));
        assertThat(point.getY().getInteger(), is(new BigInteger("463660519351695293978775992627459962966972487196635521875909448266291287923975634634090639053873258679301513736748439507889181142748412")));
    }

    @Test
    public void success_DecodePoint_11() throws DecodeException {
        // BigInteger("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439") powerPrime
        byte[] value = HexEncoder.getBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00");
        EncodedPoint encodedPoint = new EncodedPointEd448(value);
        encodedPoint.decode();
    }

    @Test(expected = DecodeException.class)
    public void success_DecodePoint_12() throws DecodeException {
        // BigInteger("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365440")
        byte[] value = HexEncoder.getBytes("00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00");
        EncodedPoint encodedPoint = new EncodedPointEd448(value);
        encodedPoint.decode();
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateEncodedPoint_1() {
        new EncodedPointEd448(new byte[56]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void failure_GenerateEncodedPoint_2() {
        new EncodedPointEd448(new byte[58]);
    }

    @Test(expected = DecodeException.class)
    public void failure_IllegalDecode_1() throws DecodeException {
        // BigInteger("93035356709837681990313447409664580397266094167976711716030745495121828878514934185752454491361736391777602765602070775492429008462675967")
        byte[] value = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 127};
        EncodedPoint encodedPoint = new EncodedPointEd448(value);
        encodedPoint.decode();
    }

    @Test(expected = DecodeException.class)
    public void failure_IllegalDecode_2() throws DecodeException {
        byte[] input = HexEncoder.getBytes("000c43838ea49d80316e3d1a637e99dc7adc3fea0c5c7852798ba6d2385b0c66044462f1913cfb34abdc3fb6d1c1039c5e1b451827534ea300");
        EncodedPoint encodedPoint = new EncodedPointEd448(input);
        encodedPoint.decode();
    }

    @Test(expected = DecodeException.class)
    public void failure_IllegalDecode_3() throws DecodeException {
        byte[] input = HexEncoder.getBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080");
        input[0] = (byte) 1;
        EncodedPoint encodedPoint = new EncodedPointEd448(input);
        encodedPoint.decode();
    }
}
