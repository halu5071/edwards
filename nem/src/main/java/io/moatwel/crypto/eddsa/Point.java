package io.moatwel.crypto.eddsa;

/**
 * A point on the eddsa curve which represents a group of {@link Coordinate}.
 */
public class Point {

    public static final Point ZERO = new Point(Coordinate.ZERO, Coordinate.ONE);

    private final Coordinate x;
    private final Coordinate y;

    /**
     * constructor of Point
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public Point(Coordinate x, Coordinate y) {
        this.x = x;
        this.y = y;
    }

    public Coordinate getX() {
        return x;
    }

    public Coordinate getY() {
        return y;
    }
}
