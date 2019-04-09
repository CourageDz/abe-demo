package com.dzy.abedemo.cpabe.timeParam;

import java.io.Serializable;

public class TimeAttKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] kj_xk;
    private byte[] lj_xk;

    public TimeAttKey(byte[] kj_xk, byte[] lj_xk) {
        this.kj_xk = kj_xk;
        this.lj_xk = lj_xk;
    }

    public byte[] getKj_xk() {
        return kj_xk;
    }

    public byte[] getLj_xk() {
        return lj_xk;
    }
}
