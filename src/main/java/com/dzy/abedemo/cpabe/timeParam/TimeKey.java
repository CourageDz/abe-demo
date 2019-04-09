package com.dzy.abedemo.cpabe.timeParam;

import java.util.HashMap;
import java.util.Map;

public class TimeKey {
    private String authority;
    private String key;
    private byte[] ljk;
    private Map<String, byte[]> userAttKeys;

    public TimeKey(String key, String authority) {
        this.key = key;
        this.authority = authority;
        userAttKeys = new HashMap<>();
    }

    public byte[] getLjk() {
        return ljk;
    }

    public void setLjk(byte[] ljk) {
        this.ljk = ljk;
    }


    public Map<String, byte[]> getUserAttKeys() {
        return userAttKeys;
    }

    public void addUserAttribute(String att, byte[] kj_xk) {
        userAttKeys.put(att, kj_xk);
    }

    public String getKey() {
        return key;
    }

    public String getAuthority() {
        return authority;
    }
}
