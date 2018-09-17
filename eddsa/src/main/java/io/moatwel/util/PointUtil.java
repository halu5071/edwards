package io.moatwel;

public class Hello {
    static {
        System.loadLibrary("hello");
    }

    public native void hello();
}
