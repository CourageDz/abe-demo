package com.dzy.abedemo.cpabe.userKey;

import java.io.Serializable;

public class CertUid implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] uUid;
    private String userID;

    public CertUid(String userID) {
        this.userID = userID;
    }

    public byte[] getuUid() {
        return uUid;
    }

    public void setuUid(byte[] uUid) {
        this.uUid = uUid;
    }

    public String getUserID() {
        return userID;
    }
}
