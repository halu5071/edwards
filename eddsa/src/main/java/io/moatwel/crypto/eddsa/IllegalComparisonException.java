package io.moatwel.crypto.eddsa;

class IllegalComparisonException extends RuntimeException {

    private static final long serialVersionUID = 8341784513L;

    IllegalComparisonException(String message) {
        super(message);
    }

    IllegalComparisonException(Throwable throwable) {
        super(throwable);
    }
}
