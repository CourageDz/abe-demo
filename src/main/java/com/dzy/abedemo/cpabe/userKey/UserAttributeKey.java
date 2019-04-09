package com.dzy.abedemo.cpabe.userKey;

import java.io.Serializable;

public class UserAttributeKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private String attribute;
    private byte[] kj_xk;


    public byte[] getKj_xk() {
        return kj_xk;
    }

    public void setKj_xk(byte[] kjk) {
        this.kj_xk = kjk;
    }

    public String getAttribute() {
        return attribute;
    }

    public UserAttributeKey(String attribute) {
        this.attribute = attribute;
    }

}
