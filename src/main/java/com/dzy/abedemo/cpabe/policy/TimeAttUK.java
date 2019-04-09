package com.dzy.abedemo.cpabe.policy;

import java.util.HashMap;
import java.util.Map;

public class TimeAttUK {
    private byte[] uk;
    private Map<Integer, byte[]> uk_x;

    public TimeAttUK(byte[] uk) {
        this.uk = uk;
        uk_x = new HashMap<>();
    }

    public Map<Integer, byte[]> getUk_x() {
        return uk_x;
    }
}
