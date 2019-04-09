package com.dzy.abedemo.cpabe.policy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EncInfo {
    private byte[] s;
    private Map<Integer, byte[]> tx;
    private Map<Integer, byte[]> timeParam;
    private Map<Integer, byte[]> lambdaParam;
    private List<Boolean> isTime;

    public EncInfo() {
        tx = new HashMap<>();
        timeParam = new HashMap<>();
        lambdaParam = new HashMap<>();
        isTime = new ArrayList<>();
    }

    public Map<Integer, byte[]> getTx() {
        return tx;
    }

    public Map<Integer, byte[]> getTimeParam() {
        return timeParam;
    }

    public Map<Integer, byte[]> getLambdaParam() {
        return lambdaParam;
    }

    public byte[] getS() {
        return s;
    }

    public void setS(byte[] s) {
        this.s = s;
    }

    public List<Boolean> getIsTime() {
        return isTime;
    }
}
