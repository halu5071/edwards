package io.moatwel.crypto.eddsa;

/**
 * Represents RuntimeException about decoding Point on edwards curve.
 * <p>Failure of decoding means a point you want to decode is not on edwards curve.
 * In this library, operation a point not on curve is not allowed.
 * This is the reason that this class is RuntimeException.
 */
public class DecodeException extends Exception {

    private static final long serialVersionUID = 128502351280931L;

    public DecodeException(String message) {
        super(message);
    }
}
