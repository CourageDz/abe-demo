package com.dzy.abedemo.cpabe.timeParam;


public class EncParam {
    private String fID;
    private byte[] param;
    private AAEncParam aaEncParam;

    public EncParam(String fID) {
        this.aaEncParam = new AAEncParam();
        this.fID = fID;
    }

    public byte[] getParam() {
        return param;
    }

    public void setParam(byte[] param) {
        this.param = param;
    }

    public String getfID() {
        return fID;
    }

    public void setfID(String fID) {
        this.fID = fID;
    }

    public AAEncParam getAaEncParam() {
        return aaEncParam;
    }

    public void setAaEncParam(AAEncParam aaEncParam) {
        this.aaEncParam = aaEncParam;
    }
}
