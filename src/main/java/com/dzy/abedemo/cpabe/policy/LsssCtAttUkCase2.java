package com.dzy.abedemo.cpabe.policy;

public class LsssCtAttUkCase2 extends LsssCtAttUk {
    private byte[] vx;

    public LsssCtAttUkCase2(byte[] k1, byte[] k2, byte[] vx) {
        super(k1, k2);
        this.vx = vx;
    }

    public byte[] getVx() {
        return vx;
    }

    public void setVx(byte[] vx) {
        this.vx = vx;
    }
}
