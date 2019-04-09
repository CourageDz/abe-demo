package com.dzy.abedemo.cpabe.policy;

public class UpdateCtComponent {
    private byte[] c2x;
    private byte[] c3x;
    private byte[] c4x;

    public UpdateCtComponent(byte[] c2x, byte[] c4x) {
        this.c2x = c2x;
        this.c4x = c4x;
    }

    public byte[] getC2x() {
        return c2x;
    }


    public byte[] getC3x() {
        return c3x;
    }

    public void setC3x(byte[] c3x) {
        this.c3x = c3x;
    }

    public byte[] getC4x() {
        return c4x;
    }

}
