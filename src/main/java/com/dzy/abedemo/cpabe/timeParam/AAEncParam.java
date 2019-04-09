package com.dzy.abedemo.cpabe.timeParam;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class AAEncParam {
    private byte[] encParam;
    private String key;
    private String authority;
    private Date begin;
    private Date end;
    private Set<String> attributes;

    public AAEncParam() {
        attributes = new HashSet<>();
    }

    public byte[] getEncParam() {
        return encParam;
    }

    public void setEncParam(byte[] encParam) {
        this.encParam = encParam;
    }

    public Date getBegin() {
        return begin;
    }

    public void setBegin(Date begin) {
        this.begin = begin;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String fID) {
        this.key = fID + begin.toString() + end.toString();
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public void addAttribtue(String... atts) {
        for (String att : atts)
            attributes.add(att);
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }
}
