package io.moatwel.crypto.eddsa.ed448;

import io.moatwel.crypto.eddsa.Coordinate;
import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class CoordinateEd448Test {

    @Test
    public void success_AddCoordinate() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("1"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("2"));

        Coordinate result = coordinate1.add(coordinate2);

        assertEquals(result.getInteger(), new BigInteger("3"));
    }

    @Test
    public void success_DivideCoordinate() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("1000"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("2"));

        Coordinate result = coordinate1.divide(coordinate2);

        assertEquals(result.getInteger(), new BigInteger("500"));
    }

    @Test
    public void success_MultiplyCoordinate() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("1000"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("2"));

        Coordinate result = coordinate1.multiply(coordinate2);

        assertEquals(result.getInteger(), new BigInteger("2000"));
    }

    @Test
    public void success_ModCoordinate() {
        Coordinate coordinate = new CoordinateEd448(new BigInteger("49729590024926883705949292896832095905118054181242336629105543669854507339847693658376641076363345491918429815972314419326143158869106070"));
        Coordinate result = coordinate.mod();

        assertThat(result.getInteger(), is(new BigInteger("304556772825615148595273960447787569070441654504708529964210125572869024510001115701686984853340368672385672566947078774505293620256218")));
    }

    @Test
    public void success_InverseCoordinate() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("100"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("101241240"));

        Coordinate result1 = coordinate1.inverse();
        Coordinate result2 = coordinate2.inverse();

        assertThat(result1.getInteger(), is(new BigInteger("298003876961198825125222761234081859084992957881800404715410981664051054548359616801422517316457383831336442629355891318031934187529830")));
        assertThat(result2.getInteger(), is(new BigInteger("673507629182422721936800389851085231159105187272243652094453137669720167156774078719049982943593330342901284365694758095842983726897167")));
    }

    @Test
    public void success_IsEqual_true_1() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("298003876961198825125222761234081859084992957881800404715410981664051054548359616801422517316457383831336442629355891318031934187529830"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("298003876961198825125222761234081859084992957881800404715410981664051054548359616801422517316457383831336442629355891318031934187529830"));

        assertThat(coordinate1.isEqual(coordinate2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("298003876961198825125222761234081859084992957881800404715410981664051054548359616801422517316457383831336442629355891318031934187529830"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("673507629182422721936800389851085231159105187272243652094453137669720167156774078719049982943593330342901284365694758095842983726897167"));

        assertThat(coordinate1.isEqual(coordinate2), is(false));
    }

    @Test
    public void success_Negate_1() {
        Coordinate coordinate1 = new CoordinateEd448(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"));
        Coordinate coordinate2 = new CoordinateEd448(new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"));
        Coordinate coordinate3 = new CoordinateEd448(new BigInteger("298003876961198825125222761234081859084992957881800404715410981664051054548359616801422517316457383831336442629355891318031934187529830"));

        Coordinate negatedCoordinate1 = coordinate1.negate();
        Coordinate negatedCoordinate2 = coordinate2.negate();
        Coordinate negatedCoordinate3 = coordinate3.negate();

        assertThat(negatedCoordinate1.getInteger(), is(new BigInteger("502258683999682590361719473788108498106851719054753926035364737493661912699324739777367190829318592647510852386697191187378895383117729")));
        assertThat(negatedCoordinate2.getInteger(), is(new BigInteger("428019514217125397873305877444073860916097320533237818185561957808280821976894896682859505043257761196106581228340174860521952955532779")));
        assertThat(negatedCoordinate3.getInteger(), is(new BigInteger("428834847334408065424101046653922675268648402805517655566079217516561273618371155884973866382219162098752441832487746043021563830835609")));
    }
}
