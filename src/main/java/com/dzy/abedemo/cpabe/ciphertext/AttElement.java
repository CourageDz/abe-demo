package com.dzy.abedemo.cpabe.ciphertext;

import java.io.Serializable;

public class AttElement implements Serializable {
    private static final long serialVersionUID = 1L;
    private String attribute;
    private boolean isTimeLimited;

    public AttElement(String attribute, boolean isTimeLimited) {
        this.attribute = attribute;
        this.isTimeLimited = isTimeLimited;
    }

    public String getAttribute() {
        return attribute;
    }

    public boolean isTimeLimited() {
        return isTimeLimited;
    }
}
