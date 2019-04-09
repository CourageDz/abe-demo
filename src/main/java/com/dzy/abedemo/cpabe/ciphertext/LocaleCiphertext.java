package com.dzy.abedemo.cpabe.ciphertext;

import java.io.Serializable;

public class LocaleCiphertext implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] c0;
    private byte[] c1;

    public LocaleCiphertext() {
    }

    public byte[] getC0() {
        return c0;
    }

    public void setC0(byte[] c0) {
        this.c0 = c0;
    }

    public byte[] getC1() {
        return c1;
    }

    public void setC1(byte[] c1) {
        this.c1 = c1;
    }
}
