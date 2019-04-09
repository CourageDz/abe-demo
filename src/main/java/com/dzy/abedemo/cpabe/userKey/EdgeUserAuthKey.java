package com.dzy.abedemo.cpabe.userKey;

import java.io.Serializable;

public class EdgeUserAuthKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] kjk;
    private byte[] ljk;

    public EdgeUserAuthKey(byte[] kjk, byte[] ljk) {
        this.kjk = kjk;
        this.ljk = ljk;
    }

    public byte[] getKjk() {
        return kjk;
    }

    public byte[] getLjk() {
        return ljk;
    }

}
