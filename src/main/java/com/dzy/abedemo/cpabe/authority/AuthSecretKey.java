package com.dzy.abedemo.cpabe.authority;

import java.io.Serializable;

public class AuthSecretKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] ai;
    private byte[] yi;

    public AuthSecretKey(byte[] ai, byte[] yi) {
        this.ai = ai;
        this.yi = yi;
    }

    public byte[] getAi() {
        return ai;
    }

    public byte[] getYi() {
        return yi;
    }
}
