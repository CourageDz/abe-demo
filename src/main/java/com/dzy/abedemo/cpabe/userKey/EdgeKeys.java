package com.dzy.abedemo.cpabe.userKey;


import com.dzy.abedemo.cpabe.timeParam.TimeAttKey;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EdgeKeys implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<String, EdgeUserAuthKey> userAuthorityKeyMap;
    private Set<String> authorities;
    private Map<String, byte[]> attributeKeyMap;
    private Map<String, TimeAttKey> timeAttKeyMap;
    private Set<String> attributes;
    private byte[] rj;

    public EdgeKeys() {
        userAuthorityKeyMap = new HashMap<>();
        authorities = new HashSet<>();
        attributeKeyMap = new HashMap<>();
        timeAttKeyMap = new HashMap<>();
        attributes = new HashSet<>();
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Set<String> attributes) {
        this.attributes.addAll(attributes);
    }

    public byte[] getRj() {
        return rj;
    }

    public void setRj(byte[] rj) {
        this.rj = rj;
    }

    public Set<String> getAuthorities() {
        return authorities;
    }

    public void addAuthorities(String authority) {
        this.authorities.add(authority);
    }

    public Map<String, EdgeUserAuthKey> getUserAuthorityKeyMap() {
        return userAuthorityKeyMap;
    }

    public EdgeUserAuthKey getEdgeUserAuthKey(String authority) {
        return userAuthorityKeyMap.get(authority);
    }

    public void addEdgeUserAuthKey(String authority, EdgeUserAuthKey edgeUserAuthKey) {
        this.userAuthorityKeyMap.put(authority, edgeUserAuthKey);
    }


    public Map<String, byte[]> getAttributeKeyMap() {
        return attributeKeyMap;
    }

    public void addAttributeKey(String attribute, byte[] attributeKey) {
        this.attributeKeyMap.put(attribute, attributeKey);
    }

    public byte[] getAttributeKey(String att) {
        return attributeKeyMap.get(att);
    }

    public Map<String, TimeAttKey> getTimeAttKeyMap() {
        return timeAttKeyMap;
    }

    public void addTimeAttKey(String attribute, TimeAttKey timeAttKey) {
        this.timeAttKeyMap.put(attribute, timeAttKey);
    }

    public TimeAttKey getTimeAttKey(String attribtue) {
        return this.timeAttKeyMap.get(attribtue);
    }
}
